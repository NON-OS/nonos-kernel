# Async Image Loading — Implementation Plan

## Problem Statement

The browser renders pages with image placeholders (`[IMG WxH]`) but cannot
fetch actual image bytes without freezing. Two approaches have failed:

1. **Render-time fetch** — `render_image()` called `load_image()` →
   `fetch_image_bytes()` → `http_client::fetch_response()` synchronously.
   This blocks the main loop, starving `poll_network()`, so TCP packets
   never arrive → deadlock.

2. **Post-render synchronous fetch** (`poll_load_images()`) — Same
   deadlock: `load_image()` uses the blocking HTTP client which waits for
   a response that never comes because the network stack isn't being polled.

Root cause: the kernel has **no async/await runtime**. All I/O is poll-based.
The existing async TCP primitives (`tcp_start_connect`, `tcp_poll_connect`,
etc.) are **global singletons** — they support exactly one connection at a
time. Navigation already occupies that slot. Image fetch needs its own.

## Solution: Dedicated Poll-Based Image Fetch Pipeline

Create `navigate/image_fetch.rs` with its own TCP socket handle, TLS
session, and reassembly buffer — completely independent of the navigation
HTTPS statics. One image is fetched at a time, driven by `poll_navigation()`
in the `LoadingImages` state, interleaved with `poll_network()` calls.

### Architecture Diagram

```
                    ┌──────────────────────────────────────────┐
                    │            Main Loop (nonos_main)         │
                    │                                          │
                    │   poll_network()   ←── drives smoltcp    │
                    │   poll_navigation()                      │
                    │       │                                  │
                    │       ├── NavState::LoadingImages         │
                    │       │       │                          │
                    │       │       ▼                          │
                    │       │   image_fetch::poll()            │
                    │       │       │                          │
                    │       │       ├── ImgState::Idle         │
                    │       │       │   pop from PENDING_IMAGES│
                    │       │       │   start DNS or connect   │
                    │       │       │                          │
                    │       │       ├── ImgState::DnsResolve   │
                    │       │       │   dns_poll() → IP        │
                    │       │       │                          │
                    │       │       ├── ImgState::Connecting   │
                    │       │       │   own socket, own handle │
                    │       │       │                          │
                    │       │       ├── ImgState::TlsHandshake │
                    │       │       │   own TLSConnection      │
                    │       │       │                          │
                    │       │       ├── ImgState::Sending      │
                    │       │       │   GET /path HTTP/1.1     │
                    │       │       │                          │
                    │       │       ├── ImgState::Receiving    │
                    │       │       │   TLS decrypt, collect   │
                    │       │       │                          │
                    │       │       └── ImgState::Decoding     │
                    │       │           JPEG/PNG → ImageData   │
                    │       │           update PAGE_RENDER     │
                    │       │           → next image or Done   │
                    │       │                                  │
                    │       └── (other NavStates use https.rs  │
                    │            statics — no conflict)        │
                    └──────────────────────────────────────────┘
```

### Why NOT Reuse async_ops/tcp.rs

```rust
// async_ops/tcp.rs — global singletons, ONE connection at a time:
static TCP_CONN_ACTIVE: AtomicBool = AtomicBool::new(false);
static TCP_CONN_ID: AtomicU32 = AtomicU32::new(0);
static TCP_HANDLE: Mutex<Option<SocketHandle>> = Mutex::new(None);
static TCP_CONNECTED: AtomicBool = AtomicBool::new(false);

pub fn tcp_start_connect(...) -> Result<u32, &'static str> {
    if TCP_CONN_ACTIVE.load(Ordering::SeqCst) {
        return Err("tcp connection already in progress");  // ← blocks us
    }
    ...
}
```

Navigation uses these globals during `NavState::Connecting..ReceivingResponse`.
Image fetch runs in `NavState::LoadingImages` (after navigation completes), so
the globals are technically free — but image fetch must create its own socket
through `NetworkStack` directly to be self-contained and avoid coupling.

### Same-Host Optimization

Most images on a page share the host with the page URL (e.g., images on
`www.google.com` are served from `www.google.com` or `www.gstatic.com`).
For the **same host** as the just-completed navigation, we can reuse the
already-resolved IP from `RESOLVED_IP`. Cross-origin hosts require a fresh
DNS lookup.

### URL Deduplication

Before starting `LoadingImages`, deduplicate the `PENDING_IMAGES` queue by
URL. If multiple `<img>` tags reference the same src, fetch once and patch
all matching placeholders.

---

## Implementation Steps

### Step 1: Create `image_fetch.rs` — Statics & State Machine

**File:** `src/apps/ecosystem/browser/navigate/image_fetch.rs`

Define the image-fetch state machine and its own connection statics:

```rust
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ImgFetchState {
    Idle = 0,
    DnsResolve = 1,
    Connecting = 2,
    TlsHandshake = 3,
    Sending = 4,
    Receiving = 5,
    Decoding = 6,
}

// ── Image-fetch–specific statics (separate from navigation) ──
static IMG_STATE: AtomicU8 = AtomicU8::new(0);  // ImgFetchState
static IMG_DEADLINE: AtomicU64 = AtomicU64::new(0);
static IMG_CONN_ID: AtomicU32 = AtomicU32::new(0);
static IMG_SOCKET_HANDLE: Mutex<Option<smoltcp::iface::SocketHandle>> = Mutex::new(None);
static IMG_TLS: Mutex<Option<TLSConnection>> = Mutex::new(None);
static IMG_REASSEMBLY: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static IMG_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static IMG_HOST: Mutex<Option<String>> = Mutex::new(None);
static IMG_PATH: Mutex<Option<String>> = Mutex::new(None);
static IMG_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);

// Track which placeholder(s) this image maps to in PAGE_RENDER
static IMG_TARGETS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

// Consecutive failure counter — bail after too many to avoid stalling
static IMG_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);
const MAX_IMG_FAILURES: u32 = 3;
const IMG_TIMEOUT_MS: u64 = 10_000;   // 10s per image (shorter than nav)
const MAX_IMG_RESPONSE: usize = 2 * 1024 * 1024;  // 2 MiB
```

### Step 2: Socket Creation (Bypassing Singletons)

Create the TCP socket directly through `NetworkStack` exactly like
`tcp_start_connect` does, but stored in `IMG_SOCKET_HANDLE`:

```rust
fn img_tcp_start(ip: [u8; 4], port: u16) -> Result<(), &'static str> {
    let ns = get_network_stack().ok_or("no network stack")?;
    let mut sockets = ns.sockets.lock();

    let rx = tcp::SocketBuffer::new(vec![0; 4096]);  // smaller than nav
    let tx = tcp::SocketBuffer::new(vec![0; 4096]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_timeout(Some(smoltcp::time::Duration::from_millis(IMG_TIMEOUT_MS)));
    let handle = sockets.add(socket);

    {
        let mut iface = ns.iface.lock();
        let s: &mut tcp::Socket = sockets.get_mut(handle);
        let endpoint = IpEndpoint::new(
            SmolIpAddress::Ipv4(SmolIpv4Address::new(ip[0], ip[1], ip[2], ip[3])),
            port,
        );
        let local_port = 49152 + ((now_ms() as u16) % 16383);
        s.connect(&mut iface.context(), endpoint, local_port)
            .map_err(|_| "img tcp connect failed")?;
    }
    drop(sockets);

    let conn_id = ns.next_id.fetch_add(1, Ordering::SeqCst);
    IMG_CONN_ID.store(conn_id, Ordering::Relaxed);

    ns.conns.lock().insert(conn_id, ConnectionEntry {
        id: conn_id, tcp: handle, last_activity_ms: now_ms(), closed: false,
    });

    *IMG_SOCKET_HANDLE.lock() = Some(handle);
    Ok(())
}
```

### Step 3: Poll Functions

Mirror the `https.rs` pattern — each function checks deadline, does one
non-blocking operation, and returns:

| Function | From State | On Success | On Failure |
|----------|-----------|------------|-----------|
| `poll_img_dns()` | `DnsResolve` | Store IP → `Connecting` | Skip image |
| `poll_img_connect()` | `Connecting` | → `TlsHandshake` | Skip image |
| `poll_img_tls()` | `TlsHandshake` | → `Sending` | Skip image |
| `poll_img_send()` | `Sending` | Build & send GET → `Receiving` | Skip image |
| `poll_img_receive()` | `Receiving` | Collect plaintext until complete → `Decoding` | Skip image |
| `poll_img_decode()` | `Decoding` | Decode JPEG/PNG → patch `PAGE_RENDER` → `Idle` | Skip image |

Each "skip image" increments `IMG_FAIL_COUNT`, cleans up the socket/TLS,
resets to `Idle`.

### Step 4: The Main Poll Entry Point

```rust
/// Called once per main-loop tick from poll_navigation() when
/// NavState == LoadingImages.
pub fn poll_image_fetch() {
    crate::network::poll_network();  // CRITICAL — drive smoltcp

    match get_img_state() {
        ImgFetchState::Idle => start_next_image(),
        ImgFetchState::DnsResolve => poll_img_dns(),
        ImgFetchState::Connecting => poll_img_connect(),
        ImgFetchState::TlsHandshake => poll_img_tls(),
        ImgFetchState::Sending => poll_img_send(),
        ImgFetchState::Receiving => poll_img_receive(),
        ImgFetchState::Decoding => poll_img_decode(),
    }
}
```

### Step 5: `start_next_image()` — Queue Consumer with Dedup

```rust
fn start_next_image() {
    // Check abort conditions
    if IMG_FAIL_COUNT.load(Ordering::Relaxed) >= MAX_IMG_FAILURES {
        finish_all_images();
        return;
    }

    let entry = super::state::PENDING_IMAGES.lock().pop();
    let (line_idx, elem_idx, url) = match entry {
        Some(e) => e,
        None => { finish_all_images(); return; }
    };

    // Collect all other entries with the same URL (dedup)
    let mut targets = vec![(line_idx, elem_idx)];
    {
        let mut queue = super::state::PENDING_IMAGES.lock();
        let mut i = 0;
        while i < queue.len() {
            if queue[i].2 == url {
                targets.push((queue[i].0, queue[i].1));
                queue.remove(i);
            } else {
                i += 1;
            }
        }
    }
    *IMG_TARGETS.lock() = targets;

    // Parse URL → host, port, path
    let (host, port, path, is_https) = parse_image_url(&url);

    // Check if same host as navigation — reuse resolved IP
    let nav_host = super::state::PENDING_HOST.lock().clone();
    let nav_ip = *super::state::RESOLVED_IP.lock();

    *IMG_HOST.lock() = Some(host.clone());
    *IMG_PATH.lock() = Some(path);
    IMG_DEADLINE.store(timestamp_millis() + IMG_TIMEOUT_MS, Ordering::Relaxed);

    if Some(&host) == nav_host.as_ref() && nav_ip.is_some() {
        // Same host — skip DNS, go straight to connect
        let ip = nav_ip.unwrap();
        *IMG_IP.lock() = Some(ip);
        match img_tcp_start(ip, port) {
            Ok(_) => set_img_state(ImgFetchState::Connecting),
            Err(_) => skip_current_image(),
        }
    } else if !is_https {
        // HTTP images — skip for now (most useful images are HTTPS)
        skip_current_image();
    } else {
        // Different host — need DNS
        *IMG_IP.lock() = None;
        match dns_start_query(&host) {
            Ok(_) => set_img_state(ImgFetchState::DnsResolve),
            Err(_) => skip_current_image(),
        }
    }
}
```

### Step 6: Wire into Navigation State Machine

**`api.rs`** — Replace placeholder `poll_load_images()`:

```rust
NavState::LoadingImages => {
    image_fetch::poll_image_fetch();
}
```

**`response.rs`** — Re-enable image collection:

```rust
// After render, collect fetchable image URLs into PENDING_IMAGES
let mut pending = PENDING_IMAGES.lock();
pending.clear();
for (line_idx, render_line) in render_output.lines.iter().enumerate() {
    for (elem_idx, elem) in render_line.elements.iter().enumerate() {
        if let engine::RenderContent::Image { ref src, .. } = elem.content {
            if !src.is_empty()
                && (src.starts_with("https://") || src.starts_with("http://"))
            {
                pending.push((line_idx, elem_idx, src.clone()));
            }
        }
    }
}
let img_count = pending.len();
drop(pending);

if img_count > 0 {
    image_fetch::reset();
    set_state(NavState::LoadingImages);
} else {
    set_state(NavState::Done);
}
```

### Step 7: Cleanup & Cancellation

**`cancel_navigation()`** in `api.rs`:

```rust
NavState::LoadingImages => {
    image_fetch::abort();
    PENDING_IMAGES.lock().clear();
}
```

**`image_fetch::abort()`**: close socket, drop TLS, reset state to Idle.

**`image_fetch::reset()`**: clear all statics, set fail count to 0.

### Step 8: DNS Sharing Concern

The DNS async ops are **also singletons** (`dns_start_query` / `dns_poll` /
`dns_cancel`). Image fetches that need DNS for a different host will
conflict if navigation somehow triggers DNS concurrently. But since image
loading only runs in `LoadingImages` state (after navigation is fully
done), the DNS singletons are free. No conflict.

If this assumption ever breaks (e.g., background navigation), DNS must
be duplicated the same way TCP was.

### Step 9: Tests

| # | Test | Validates |
|---|------|-----------|
| 1 | `test_img_fetch_state_machine` | State transitions: Idle → DnsResolve → Connecting → ... → Idle |
| 2 | `test_pending_images_dedup` | Same URL appears 3× → fetch once, patch 3 elements |
| 3 | `test_skip_data_uri_images` | `data:image/png;base64,...` not added to queue |
| 4 | `test_skip_empty_src` | `src=""` not added to queue |
| 5 | `test_max_failure_bail` | After `MAX_IMG_FAILURES` consecutive failures → Done |
| 6 | `test_same_host_skips_dns` | If image host matches nav host → DNS step skipped |
| 7 | `test_timeout_cleans_up` | Socket + TLS dropped on deadline expiry |
| 8 | `test_cancellation_clears_state` | `abort()` resets all statics |

---

## File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `navigate/image_fetch.rs` | **CREATE** | New module: state machine, statics, TCP/TLS/decode pipeline |
| `navigate/mod.rs` | **EDIT** | Add `mod image_fetch;` |
| `navigate/api.rs` | **EDIT** | Wire `poll_image_fetch()` into `LoadingImages`, replace `poll_load_images()` |
| `navigate/response.rs` | **EDIT** | Re-enable image collection → `PENDING_IMAGES`, transition to `LoadingImages` |
| `navigate/state.rs` | **NONE** | Already has `LoadingImages = 9` and `PENDING_IMAGES` — no changes needed |
| `engine/image_loader.rs` | **NONE** | Used for decode only (not fetch) — existing code works |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| smoltcp socket leak on error path | Memory leak, socket exhaustion | `img_cleanup()` called on every error/skip/cancel path |
| DNS singleton collision | Deadlock or wrong IP | Image loading runs only after nav is Done — DNS is free. Assert this invariant. |
| Large image stalls main loop during decode | Input lag | Cap decode at 2 MiB, 4096×4096. If decode takes >50ms, defer to next tick (future optimization). |
| TLS handshake for CDN hosts (different cert chain) | Slow or fail | Use same cert verifier as navigation. Accept failure gracefully — image stays as placeholder. |
| Memory pressure from multiple decoded images | OOM | `MAX_IMAGES_PER_PAGE = 8` cap already enforced. Decoded images share `PAGE_RENDER` lifecycle. |

---

## Success Criteria

| Metric | Before | After |
|--------|--------|-------|
| Google.com images | `[IMG 20x20]` placeholder | Decoded pixels displayed |
| Main loop responsiveness | N/A (frozen or no images) | Input/display responsive during fetch |
| `make run-serial` | No freeze | No freeze, serial shows `[IMG-FETCH]` progress |
| Duplicate image fetches | N/A | Fetched once, patched everywhere |
| Failure mode | Hang forever | Skip after 10s, bail after 3 failures |
