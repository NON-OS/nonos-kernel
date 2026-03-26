# Browser Next Sprint — Implementation Plan

## Overview

Five high-impact features to close the biggest real-world usability gaps in the NØNOS
browser. Ordered by dependency chain and bang-for-buck: each item unblocks tangible
improvements on real websites.

**Prerequisites complete:**
- TLS 1.3 — 3 cipher suites, 7 sig algs, dual key share, HRR, 26 root CAs ✅
- HTTP/1.1 — redirects, cookies, gzip/deflate, chunked encoding ✅
- DNS — A/AAAA/CNAME/MX/TXT, caching, DoH config ✅
- HTML parser — DOM tree, 30+ elements, script/style stripping ✅
- Image rendering — PNG decode + SVG subset ✅
- JS engine — custom tree-walking interpreter with lexer, parser, DOM bindings ✅

---

## Sprint Items

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 1 | [TLS Session Resumption (PSK/Tickets)](#phase-1--tls-session-resumption) | Every HTTPS sub-resource does a full handshake today (~300ms each). Resumption cuts to 1-RTT. | Medium |
| 2 | [HTTP Connection Pooling](#phase-2--http-connection-pooling) | Every request opens + tears down TCP+TLS. Pooling reuses connections across requests to the same host. | Medium |
| 3 | [Brotli Decompression](#phase-3--brotli-decompression) | Most CDNs prefer brotli. Without it, responses arrive ~30% larger or the server may refuse to compress at all. | Small |
| 4 | [Form Submission](#phase-4--form-submission) | `Form`/`FormInput` types exist but nothing wires POST/GET submission — login, search, checkout all broken. | Medium |
| 5 | [JPEG Decoding](#phase-5--jpeg-decoding) | ~80% of web images are JPEG; currently only PNG renders. | Medium-Large |

---

## Phase 1 — TLS Session Resumption

**Goal:** After a full TLS 1.3 handshake, cache the server's NewSessionTicket and use
it for PSK-based 1-RTT resumption on subsequent connections to the same host.

### Current State

- `TLSConnection` performs a full handshake every time (`start_handshake` → `poll_handshake` loop)
- `NewSessionTicket` messages (post-handshake, type 0x04) arrive as encrypted handshake records after the handshake completes — currently silently ignored in `process_hs()`
- `KeySchedule` derives `resumption_master_secret` material but doesn't store it
- `TlsSessionInfo` only holds cipher suite + traffic secrets — no resumption data
- No session cache exists

### Design

```
                          ┌─────────────────────┐
                          │   SessionCache       │
                          │   (per-host LRU)     │
                          ├─────────────────────┤
                          │ host → SessionTicket │
                          │ max_entries: 64      │
                          │ ttl: min(ticket_lt,  │
                          │      7 days)         │
                          └─────────────────────┘
                                ▲           │
                   store_ticket │           │ get_ticket
                                │           ▼
    ┌───────────┐     ┌────────────────┐     ┌───────────────┐
    │ Full HS   │────▶│ NewSessionTkt  │     │ PSK ClientHi  │
    │ (current) │     │ parse + cache  │     │ (resumption)  │
    └───────────┘     └────────────────┘     └───────────────┘
```

### Files

| Action | File | Purpose |
|--------|------|---------|
| **New** | `src/network/onion/tls/session.rs` | `SessionTicket`, `SessionCache`, LRU eviction |
| Modify | `src/network/onion/tls/connection/types.rs` | Add `resumption_secret` field to `TLSConnection` |
| Modify | `src/network/onion/tls/keys.rs` | `derive_resumption_master_secret()` after application keys |
| Modify | `src/network/onion/tls/connection/app.rs` | Parse NewSessionTicket from post-handshake app data |
| Modify | `src/network/onion/tls/protocol.rs` | `parse_new_session_ticket()`, `build_psk_client_hello()` |
| Modify | `src/network/onion/tls/connection/start.rs` | Add PSK extension + binder to ClientHello when ticket available |
| Modify | `src/network/onion/tls/connection/poll_hello.rs` | Handle `pre_shared_key` extension in ServerHello |
| Modify | `src/network/onion/tls/mod.rs` | Re-export `SessionCache` |
| Modify | `src/network/http_client/client.rs` | Pass `SessionCache` through HTTPS request path |

### Implementation Steps

1. **Define `SessionTicket` struct:**
   ```rust
   pub struct SessionTicket {
       pub ticket: Vec<u8>,          // opaque ticket data
       pub lifetime_secs: u32,       // server-specified max age
       pub age_add: u32,             // obfuscated_ticket_age offset
       pub nonce: Vec<u8>,           // per-ticket nonce
       pub cipher_suite: CipherSuite,
       pub resumption_secret: [u8; 48], // derived from resumption_master_secret
       pub created_ms: u64,          // timestamp for age calculation
       pub max_early_data: u32,      // 0 = no early data (we won't implement 0-RTT initially)
   }
   ```

2. **Define `SessionCache` (LRU, capacity 64):**
   - Key: `(host, port)` — stored as `String`
   - Lock: `spin::Mutex` (no allocation in lock path)
   - Eviction: oldest-first when full
   - TTL enforcement: check `created_ms + lifetime_secs * 1000` on lookup

3. **Derive resumption master secret** in `KeySchedule::derive_application()`:
   - After deriving app traffic secrets, also compute:
     `resumption_master_secret = HKDF-Expand-Label(master_prk, "res master", transcript_hash)`
   - Store in new `TLSConnection.resumption_secret` field

4. **Parse NewSessionTicket** (HSType 0x04):
   - In `TLSConnection::decrypt_app()` or a new `process_post_handshake()`:
     after decrypting an app-data record, check if inner type is Handshake
   - Parse: `lifetime(4) || age_add(4) || nonce_len(1) || nonce || ticket_len(2) || ticket || extensions_len(2) || extensions`
   - Derive per-ticket PSK: `HKDF-Expand-Label(resumption_secret, "resumption", nonce, hash_len)`
   - Store `SessionTicket` in cache

5. **PSK in ClientHello:**
   - On `start_handshake()`, check cache for `(host, port)`
   - If ticket found and not expired:
     - Add `pre_shared_key` extension (type 0x0029) with PskIdentity + binder
     - Add `psk_key_exchange_modes` extension (type 0x002D) with `psk_dhe_ke` (0x01)
     - Binder = HMAC over partial ClientHello transcript (truncated before binders)
   - Still include key_share for `psk_dhe_ke` mode (not pure PSK, which has no forward secrecy)

6. **ServerHello PSK acceptance:**
   - If ServerHello contains `pre_shared_key` extension (selected_identity = 0):
     - Skip certificate verification (server authenticated via PSK)
     - Use cached PSK as input to `derive_after_sh()` instead of `zeros`
     - Otherwise proceed as normal full handshake

### Checklist

- [x] Define `SessionTicket` struct with zeroization on `Drop`
- [x] Implement `SessionCache` with `spin::Mutex`, LRU eviction, TTL
- [x] Add `derive_resumption_master_secret()` to `KeySchedule`
- [x] Store `resumption_secret` in `TLSConnection` (zeroized on Drop)
- [x] Parse `NewSessionTicket` in post-handshake path
- [x] Derive per-ticket PSK via `HKDF-Expand-Label(resumption_secret, "resumption", nonce)`
- [x] Build `pre_shared_key` + `psk_key_exchange_modes` ClientHello extensions
- [x] Compute binder HMAC over truncated transcript
- [x] Handle PSK acceptance in ServerHello
- [x] Adjust `derive_after_sh()` to accept PSK as early secret input
- [x] Wire `SessionCache` through `HttpClient` → HTTPS request path
- [x] Tests: session cache store/get/eviction/clear
- [x] Tests: expired ticket TTL enforcement
- [x] Tests: zeroization of secrets on Drop
- [x] Tests: NewSessionTicket parsing (basic, early_data, too_short)
- [x] Tests: PSK extension structure + psk_ke_modes
- [x] Tests: obfuscated ticket age computation

---

## Phase 2 — HTTP Connection Pooling

**Goal:** Reuse TCP+TLS connections across multiple HTTP requests to the same host,
eliminating repeated handshake overhead for page sub-resources.

### Current State

- `HttpClient::request()` creates a new TCP socket + TLS connection per request
- `HttpRequestOptions.keep_alive` exists but defaults to `false` and sends `Connection: close`
- `HttpResponse::is_keep_alive()` parses `Connection: keep-alive` but result is unused
- No connection pool or reuse mechanism exists
- After each request, the socket is dropped (TCP closes)

### Design

```
    HttpClient
        │
        ▼
    ┌────────────────────────────┐
    │      ConnectionPool        │
    │  spin::Mutex<BTreeMap<     │
    │    (host,port),            │
    │    Vec<PooledConnection>   │
    │  >>                        │
    ├────────────────────────────┤
    │ acquire(host, port, tls)   │──▶ reuse idle or create new
    │ release(conn)              │──▶ return to pool if keep-alive
    │ evict_stale()              │──▶ close idle > 60s
    └────────────────────────────┘
```

### Files

| Action | File | Purpose |
|--------|------|---------|
| **New** | `src/network/http_client/pool.rs` | `ConnectionPool`, `PooledConnection`, acquire/release/evict |
| Modify | `src/network/http_client/client.rs` | Use pool in `do_request()` / `do_https_request()` |
| Modify | `src/network/http_client/request.rs` | Default `keep_alive: true`, send `Connection: keep-alive` |
| Modify | `src/network/http_client/mod.rs` | Re-export pool, declare module |
| Modify | `src/network/tcp/socket.rs` | Add `is_connected()` health check method |

### Implementation Steps

1. **Define `PooledConnection`:**
   ```rust
   pub struct PooledConnection {
       pub socket: TcpSocket,
       pub tls: Option<TLSConnection>,  // None for plain HTTP
       pub last_used_ms: u64,
       pub request_count: u32,          // max 100 requests per connection
   }
   ```

2. **Define `ConnectionPool`:**
   - Key: `String` (format: `"host:port:tls"`)
   - Max idle connections per host: 6 (matches browser conventions)
   - Max total idle connections: 32
   - Idle timeout: 60 seconds
   - Max requests per connection: 100

3. **`acquire()` logic:**
   - Lock pool → find idle connection for `(host, port, is_tls)`
   - Health-check: verify socket is still connected (not FIN'd)
   - If healthy, remove from pool and return
   - If none available, create new TCP connection (+ TLS handshake if HTTPS)
   - Use `SessionCache` (Phase 1) for TLS resumption on new connections

4. **`release()` logic:**
   - If response had `Connection: close` or max requests reached → drop
   - Otherwise, update `last_used_ms`, push back into pool
   - If pool is over capacity, evict oldest

5. **`evict_stale()` — called periodically:**
   - Remove connections idle > 60 seconds
   - Called from a timer tick or at start of `acquire()`

6. **Wire into `HttpClient`:**
   - `HttpClient` holds `Arc<ConnectionPool>` (or static global)
   - `do_request()` / `do_https_request()`: `acquire()` at start, `release()` at end
   - On request failure: drop connection (don't return to pool)

### Checklist

- [x] Define `PooledConnection` struct
- [x] Implement `ConnectionPool` with `spin::Mutex<BTreeMap>`
- [x] Implement `acquire()` with health check
- [x] Implement `release()` with capacity enforcement
- [x] Implement `evict_stale()` with idle timeout
- [x] Health check via `tcp_is_closed()` in acquire
- [x] Default `keep_alive: true` in `HttpRequestOptions`
- [x] Send `Connection: keep-alive` header by default
- [x] Wire pool into `HttpClient.do_https_request()`
- [x] Handle `Connection: close` response - don't return to pool
- [x] Integrate `SessionCache` for new TLS connections
- [x] Tests: pool key format (TLS vs plain separation)
- [x] Tests: stale connection eviction (evict_stale + evict_stale_vec)
- [x] Tests: max connections per host enforcement (per-host limit)
- [x] Tests: Connection: close prevents reuse (release_no_keep_alive_drops)
- [x] Tests: max requests per connection drops
- [x] Tests: total pool capacity limit
- [x] Tests: clear empties pool
- [x] Tests: different hosts stored separately

---

## Phase 3 — Brotli Decompression

**Goal:** Decode `Content-Encoding: br` responses so the browser can receive brotli-
compressed content from modern CDNs (Cloudflare, Akamai, Fastly, etc.).

### Current State

- `decompress_body()` in `navigate/decompress.rs` handles `gzip` and `deflate` via `miniz_oxide`
- The `"br"` match arm returns raw bytes unchanged — a no-op passthrough
- `Accept-Encoding` header in `request.rs` does not advertise `br`
- No brotli decompression code exists anywhere in the kernel

### Design

Brotli decompression is a pure data transform (compressed bytes → decompressed bytes).
The `brotli` crate (by Dropbox) is `no_std` compatible and works with a custom allocator.
Alternatively, a minimal decoder can be implemented from the RFC 7932 spec.

**Recommended approach:** Use the `brotli-decompressor` crate (pure Rust, `no_std`, ~20KB
binary size increase) rather than implementing from scratch. Brotli's format is complex
(context modeling, huffman + ANS, dictionary) and a hand-rolled decoder would be error-prone.

### Files

| Action | File | Purpose |
|--------|------|---------|
| Modify | `Cargo.toml` | Add `brotli-decompressor` dependency (no_std, feature-gated) |
| Modify | `src/apps/ecosystem/browser/navigate/decompress.rs` | Implement `decompress_brotli()` |
| Modify | `src/network/http_client/request.rs` | Add `br` to `Accept-Encoding` header |

### Implementation Steps

1. **Add dependency** in `Cargo.toml`:
   ```toml
   [dependencies]
   brotli-decompressor = { version = "4", default-features = false, features = ["alloc"], optional = true }

   [features]
   nonos-brotli = ["brotli-decompressor"]
   ```

2. **Implement `decompress_brotli()`:**
   ```rust
   #[cfg(feature = "nonos-brotli")]
   fn decompress_brotli(data: &[u8]) -> Option<Vec<u8>> {
       use brotli_decompressor::BrotliDecompress;
       let mut output = Vec::new();
       let mut reader = data;
       BrotliDecompress(&mut reader, &mut output).ok()?;
       Some(output)
   }
   ```

3. **Update `decompress_body()`:**
   ```rust
   Some("br") => {
       #[cfg(feature = "nonos-brotli")]
       { decompress_brotli(body).unwrap_or_else(|| body.to_vec()) }
       #[cfg(not(feature = "nonos-brotli"))]
       { body.to_vec() }
   }
   ```

4. **Advertise `br` in `Accept-Encoding`:**
   - In `build_request()`, change:
     `Accept-Encoding: gzip, deflate` → `Accept-Encoding: gzip, deflate, br`
   - Only advertise `br` when `nonos-brotli` feature is enabled

### Checklist

- [x] Add `brotli-decompressor` to `Cargo.toml` under `nonos-brotli` feature
- [x] Add `nonos-brotli` to the `std` feature for test builds
- [x] Implement `decompress_brotli()` in `decompress.rs`
- [x] Wire into `decompress_body()` match arm
- [x] Add `br` to `Accept-Encoding` header (feature-gated)
- [x] Tests: decompress known brotli payload
- [x] Tests: graceful fallback on corrupt brotli data
- [x] Tests: feature-gate disabling returns raw bytes

---

## Phase 4 — Form Submission

**Goal:** Wire the existing `Form`/`FormInput` DOM types into actual HTTP requests so
that login forms, search boxes, and other form interactions work.

### Current State

- `Form` struct exists: `{ action: String, method: String, inputs: Vec<FormInput> }`
- `FormInput` struct exists: `{ name, input_type, value, placeholder }`
- HTML parser populates `Form` objects into the `Document` (linked from form elements)
- `HttpClient` has `post()` method that accepts a body
- **No code connects form submission to HTTP requests**
- No URL-encoded form body builder
- No multipart/form-data encoder
- No form UI interaction (input fields, submit buttons)

### Design

```
    User clicks Submit button
            │
            ▼
    ┌──────────────────┐
    │ collect_form_data│  Gather name=value pairs from FormInputs
    └──────────────────┘
            │
            ▼
    ┌──────────────────┐
    │ encode_form_body │  URL-encode (GET query / POST body)
    └──────────────────┘
            │
            ▼
    ┌──────────────────┐
    │ submit_form()    │  Build URL, dispatch via HttpClient or navigate
    └──────────────────┘
            │
            ▼
    ┌──────────────────┐
    │ navigate to      │  Process response as new page load
    │ response         │
    └──────────────────┘
```

### Files

| Action | File | Purpose |
|--------|------|---------|
| **New** | `src/apps/ecosystem/browser/form/mod.rs` | Form submission module |
| **New** | `src/apps/ecosystem/browser/form/encode.rs` | URL encoding + form body building |
| **New** | `src/apps/ecosystem/browser/form/submit.rs` | Form collection, submission dispatch |
| Modify | `src/apps/ecosystem/browser/mod.rs` | Declare `form` module |
| Modify | `src/apps/ecosystem/browser/navigate/api.rs` | Add `navigate_with_post()` entry point |
| Modify | `src/apps/ecosystem/browser/engine/types/form.rs` | Add form index/id for lookup |

### Implementation Steps

1. **URL encoding (`encode.rs`):**
   ```rust
   pub fn url_encode(input: &str) -> String {
       // RFC 3986: encode all non-unreserved characters
       // unreserved = A-Z a-z 0-9 - _ . ~
       // space → +  (application/x-www-form-urlencoded)
   }

   pub fn build_form_urlencoded(pairs: &[(String, String)]) -> String {
       // name1=value1&name2=value2
   }
   ```

2. **Form data collection (`submit.rs`):**
   ```rust
   pub fn collect_form_data(form: &Form) -> Vec<(String, String)> {
       form.inputs.iter()
           .filter(|i| !i.name.is_empty())
           .filter(|i| i.input_type != "submit" && i.input_type != "button")
           .map(|i| (i.name.clone(), i.value.clone()))
           .collect()
   }
   ```

3. **Form submission dispatch:**
   ```rust
   pub fn submit_form(form: &Form, base_url: &str) -> Result<(), &'static str> {
       let data = collect_form_data(form);
       let action_url = resolve_url(&form.action, base_url);
       match form.method.to_ascii_uppercase().as_str() {
           "GET" => {
               let query = build_form_urlencoded(&data);
               let url = format!("{}?{}", action_url, query);
               navigate(&url);
           }
           "POST" | _ => {
               let body = build_form_urlencoded(&data);
               navigate_with_post(&action_url, body.as_bytes(),
                   "application/x-www-form-urlencoded");
           }
       }
   }
   ```

4. **Navigation POST support:**
   - Add `navigate_with_post(url, body, content_type)` to `navigate/api.rs`
   - Sends body with `Content-Type` and `Content-Length` headers
   - Response processed same as GET navigation

5. **UI integration (future):**
   - Input fields: capture keyboard input into `FormInput.value`
   - Submit button click: trigger `submit_form()`
   - This phase focuses on the plumbing; UI polish is follow-up work

### Checklist

- [x] Implement `url_encode()` (RFC 3986 percent-encoding)
- [x] Implement `build_form_urlencoded()` for name=value pairs
- [x] Implement `collect_form_data()` from `Form` struct
- [x] Implement `resolve_url()` for relative action URLs
- [x] Implement `submit_form()` dispatch (GET query string / POST body)
- [x] Add `navigate_with_post()` to navigate API
- [x] Wire POST body into `HttpClient::request()` with Content-Type
- [x] Add form index/id to `Form` struct for lookup from render
- [x] Tests: URL encoding of special characters
- [x] Tests: form data collection filters submit/button inputs
- [x] Tests: GET form appends query string
- [x] Tests: POST form sends urlencoded body
- [x] Tests: relative action URL resolution

---

## Phase 5 — JPEG Decoding

**Goal:** Decode baseline JPEG images (the most common web image format, ~80% of images)
and render them in the browser alongside existing PNG support.

### Current State

- PNG decoder exists in `src/apps/ecosystem/browser/engine/png/` (chunks, filter, decode)
- PNG produces `ImageData { width, height, pixels: Vec<u32> }` (ARGB)
- `Image` struct: `{ src, alt, width, height }`
- No JPEG decoder exists
- Render pipeline shows images when `ImageData` is available
- `miniz_oxide` already available for inflate (used by PNG + gzip)

### Design

Implement a baseline JPEG decoder (JFIF/EXIF) supporting:
- **Baseline DCT** (SOF0) — covers ~95% of web JPEGs
- **YCbCr → RGB** color conversion
- **4:2:0, 4:2:2, 4:4:4** chroma subsampling
- **Huffman decoding** (DHT markers)
- **Dequantization** (DQT markers)
- **8×8 IDCT** (Inverse Discrete Cosine Transform)

NOT implementing initially:
- Progressive JPEG (SOF2) — defer to follow-up
- Arithmetic coding — rare on web
- CMYK color space — print-only
- ICC color profiles — accuracy not critical for display

```
    JPEG bytes
        │
        ▼
    ┌────────────┐     ┌────────────┐     ┌────────────┐
    │ Parse JFIF │────▶│ Decode MCU │────▶│ YCbCr→RGB  │
    │ markers    │     │ (Huffman + │     │ + output   │
    │ SOI,DHT,   │     │  IDCT +    │     │ ImageData  │
    │ DQT,SOF,   │     │  dequant)  │     │            │
    │ SOS,EOI    │     └────────────┘     └────────────┘
    └────────────┘
```

### Files

| Action | File | Purpose |
|--------|------|---------|
| **New** | `src/apps/ecosystem/browser/engine/jpeg/mod.rs` | Module root, `decode_jpeg()` public API |
| **New** | `src/apps/ecosystem/browser/engine/jpeg/markers.rs` | JFIF marker parsing (SOI, SOF, DHT, DQT, SOS, EOI) |
| **New** | `src/apps/ecosystem/browser/engine/jpeg/huffman.rs` | Huffman table construction + bit-stream decoding |
| **New** | `src/apps/ecosystem/browser/engine/jpeg/dct.rs` | 8×8 IDCT + dequantization |
| **New** | `src/apps/ecosystem/browser/engine/jpeg/color.rs` | YCbCr → RGB conversion, chroma upsampling |
| Modify | `src/apps/ecosystem/browser/engine/mod.rs` | Declare `jpeg` module, re-export `decode_jpeg` |
| Modify | `src/apps/ecosystem/browser/navigate/response.rs` | Route `.jpg`/`.jpeg` content to JPEG decoder |

### Implementation Steps

1. **Marker parser (`markers.rs`):**
   - Scan for 0xFF marker bytes
   - Parse: SOI (0xFFD8), SOF0 (0xFFC0), DHT (0xFFC4), DQT (0xFFDB), SOS (0xFFDA), EOI (0xFFD9)
   - Extract: image dimensions, component info (Y/Cb/Cr), sampling factors
   - Extract: quantization tables (up to 4), Huffman tables (up to 4 DC + 4 AC)
   - Skip: APP0/APP1 (JFIF/EXIF metadata), COM (comments)

2. **Huffman decoder (`huffman.rs`):**
   - Build Huffman tree from DHT marker data (code lengths + symbols)
   - Bit-stream reader: read N bits from entropy-coded data
   - Decode DC coefficients (differential coding)
   - Decode AC coefficients (run-length + Huffman)
   - Handle restart markers (RST0-RST7, 0xFFD0-0xFFD7)

3. **IDCT + dequantization (`dct.rs`):**
   ```rust
   pub fn idct_8x8(coefficients: &mut [i32; 64], quant_table: &[u16; 64]) {
       // 1. Dequantize: coeff[i] *= quant_table[i]
       // 2. Zigzag reorder to 8×8
       // 3. Apply 2D IDCT (separable: row IDCT then column IDCT)
       // 4. Level shift: add 128, clamp to [0, 255]
   }
   ```
   - Use integer IDCT (AAN algorithm) for performance — no floating point
   - Zigzag scan order: standard JPEG zigzag table

4. **Color conversion (`color.rs`):**
   ```rust
   pub fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
       // ITU-R BT.601:
       // R = Y + 1.402 * (Cr - 128)
       // G = Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128)
       // B = Y + 1.772 * (Cb - 128)
       // Use fixed-point integer arithmetic (no f32/f64!)
   }
   ```
   - Chroma upsampling for 4:2:0/4:2:2: bilinear interpolation on Cb/Cr planes
   - Output: ARGB `u32` pixels matching `ImageData` format

5. **Top-level `decode_jpeg()`:**
   ```rust
   pub fn decode_jpeg(data: &[u8]) -> Option<ImageData> {
       let markers = parse_markers(data)?;
       if markers.sof.coding != Baseline { return None; } // only SOF0
       let pixels = decode_scan(&markers)?;
       Some(ImageData { width: markers.sof.width, height: markers.sof.height, pixels })
   }
   ```

6. **Integration:**
   - In image rendering path, try `decode_jpeg()` when Content-Type is `image/jpeg`
     or data starts with `0xFF 0xD8` (JPEG SOI marker)
   - Falls through to PNG decoder if JPEG decode fails

### Checklist

- [x] Implement JFIF marker parser (SOI, SOF0, DHT, DQT, SOS, EOI)
- [x] Parse component info and sampling factors
- [x] Build Huffman tables from DHT data
- [x] Implement bit-stream reader
- [x] Decode DC coefficients (differential)
- [x] Decode AC coefficients (run-length)
- [x] Implement zigzag reorder table
- [x] Implement integer 8×8 IDCT (AAN algorithm)
- [x] Implement dequantization
- [x] Implement YCbCr → RGB (fixed-point, no floats)
- [x] Implement chroma upsampling (4:2:0, 4:2:2)
- [x] Handle restart markers
- [x] Top-level `decode_jpeg()` → `ImageData`
- [x] Wire into image render path (Content-Type / magic bytes detection)
- [x] Declare `jpeg` module in `engine/mod.rs`
- [x] Tests: decode 1×1 MCU baseline JPEG
- [x] Tests: decode multi-MCU image with 4:2:0 subsampling
- [x] Tests: reject progressive JPEG gracefully (return None)
- [x] Tests: reject truncated/corrupt JPEG gracefully
- [x] Tests: verify RGB output against known reference values
- [x] Size limit: reject images > 4096×4096 (consistent with PNG decoder)

---

## Dependency Graph

```
Phase 1: TLS Session Resumption
    │
    ▼
Phase 2: HTTP Connection Pooling  ◄── uses SessionCache from Phase 1
    │
    │   Phase 3: Brotli (independent)
    │   Phase 4: Forms (independent)
    │   Phase 5: JPEG  (independent)
    │
    ▼
 Phases 3-5 can proceed in parallel after Phase 2
```

Phases 3, 4, and 5 are independent of each other and can be implemented in any order.
Phase 2 benefits from Phase 1 (resumed connections in the pool) but can be implemented
concurrently if the pool initially creates full-handshake connections.

---

## Success Criteria

After all 5 phases:

| Metric | Before | After |
|--------|--------|-------|
| HTTPS sub-resource handshake | ~300ms full each | ~100ms 1-RTT resumed |
| Connections per page load | N (one per resource) | ~6 (pooled per host) |
| Brotli-compressed pages | Fail or 30% larger | Decompress correctly |
| Form login/search | Non-functional | Working (GET + POST) |
| Web images displayable | PNG only (~20%) | PNG + JPEG (~95%) |

---

## What's After This Sprint

These five items are the highest-impact next steps. The following are candidates for
subsequent sprints, roughly prioritized:

1. **CSS Box Model** — margin, padding, border, width/height → real layout
2. **CSS Selectors** — class/id/element matching to apply stylesheet rules
3. **HTTP/2** — multiplexed streams, HPACK header compression
4. **Table Layout** — column sizing, cell alignment, rowspan/colspan
5. **Font Rendering** — variable sizes, bold/italic, TrueType basics
6. **TLS 1.2 Fallback** — for legacy/enterprise servers
7. **Progressive JPEG** — multi-pass rendering for large images
8. **WebP/GIF** — additional image formats

---

## Sprint 2 — Image Loading & No-JS Form Rendering

Two phases that close the gap between having decoders and actually displaying content.

### Phase 6 — Image Loading Pipeline

**Goal:** When the render engine encounters `<img src="...">`, fetch the image bytes,
detect format, decode to `ImageData`, and emit `RenderContent::DecodedImage` so the
graphics layer blits actual pixels instead of the `[IMG WxH]` placeholder.

**Files to create/modify:**

| File | Purpose |
|------|---------|
| `engine/image_loader.rs` (new) | `load_image(src, base_url) -> Option<ImageData>` — resolve relative URL, HTTP GET, detect format, decode |
| `engine/render/elements.rs` (mod) | `render_image()` calls `load_image()`, emits `DecodedImage` on success, falls back to placeholder |
| `engine/render/page.rs` (mod) | Pass base URL into render context so relative `src` can be resolved |
| `engine/render/context.rs` (mod) | Add `base_url: String` field to `RenderContext` |
| `navigate/response.rs` (mod) | Pass page URL to `render_page()` |

**Implementation details:**

1. **URL resolution:**
   ```rust
   fn resolve_url(src: &str, base_url: &str) -> Option<String> {
       if src.starts_with("http://") || src.starts_with("https://") {
           Some(String::from(src))
       } else if src.starts_with("//") {
           // protocol-relative
           let scheme = if base_url.starts_with("https") { "https:" } else { "http:" };
           Some(alloc::format!("{}{}", scheme, src))
       } else if src.starts_with('/') {
           // absolute path — extract origin from base_url
           extract_origin(base_url).map(|o| alloc::format!("{}{}", o, src))
       } else {
           // relative path
           extract_base_path(base_url).map(|b| alloc::format!("{}{}", b, src))
       }
   }
   ```

2. **Format detection (magic bytes):**
   ```rust
   fn detect_image_format(data: &[u8]) -> ImageFormat {
       if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
           ImageFormat::Jpeg
       } else if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
           ImageFormat::Png
       } else {
           ImageFormat::Unknown
       }
   }
   ```

3. **Decode dispatch:**
   ```rust
   pub fn load_image(src: &str, base_url: &str) -> Option<ImageData> {
       let url = resolve_url(src, base_url)?;
       let data = fetch_image_bytes(&url)?;
       match detect_image_format(&data) {
           ImageFormat::Jpeg => decode_jpeg(&data),
           ImageFormat::Png  => decode_png(&data),
           ImageFormat::Unknown => None,
       }
   }
   ```

4. **Render integration:**
   - `render_image()` attempts `load_image(src, ctx.base_url)`
   - On success: emit `RenderContent::DecodedImage { data }`
   - On failure: fall back to current placeholder `RenderContent::Image { alt, ... }`
   - Limit: skip fetch for images > 2 MiB response, > 4096×4096 decoded

5. **HTTP fetch for images:**
   - Reuse existing HTTP client / connection pool from Phase 2
   - Accept header: `image/jpeg, image/png, */*`
   - Follow redirects (existing redirect logic)
   - Timeout: 10s per image, max 8 images per page load

### Checklist

- [x] Create `engine/image_loader.rs` with `load_image()`, `resolve_url()`, `detect_image_format()`
- [x] Add `ImageFormat` enum (Jpeg, Png, Unknown)
- [x] Implement URL resolution (absolute, protocol-relative, path-relative)
- [x] Implement format detection via magic bytes
- [x] Implement `fetch_image_bytes()` using existing HTTP client
- [x] Wire `load_image()` into `render_image()` in `elements.rs`
- [x] Add `base_url` to `RenderContext`
- [x] Pass page URL through `render_page()` → `RenderContext`
- [x] Update `response.rs` to pass URL to `render_page()`
- [x] Emit `RenderContent::DecodedImage` on successful decode
- [x] Fall back to placeholder on decode failure
- [x] Enforce 2 MiB fetch limit and 4096×4096 decode limit
- [x] Limit concurrent image fetches (max 8 per page)
- [x] Tests: resolve absolute URL
- [x] Tests: resolve relative URL
- [x] Tests: resolve protocol-relative URL
- [x] Tests: detect JPEG magic bytes
- [x] Tests: detect PNG magic bytes
- [x] Tests: unknown format returns None
- [x] Tests: load_image with valid JPEG bytes → ImageData
- [x] Tests: load_image with invalid data → None

---

### Phase 7 — No-JS Form Rendering & `<noscript>` Support

**Goal:** Render HTML `<form>` elements with their `<input>`, `<select>`, `<textarea>`,
and submit buttons so that sites like Google Search work without JavaScript. Parse
`<noscript>` blocks as visible content (since we have no JS engine).

**Why Google doesn't work today:** Google wraps its search form in `<noscript>` tags
(fallback for no-JS browsers) and hides the JS-dependent version. Our parser currently
skips `<noscript>` content, so the form never renders.

**Files to create/modify:**

| File | Purpose |
|------|---------|
| `engine/parser/noscript.rs` (new) | Parse `<noscript>` blocks as visible content |
| `engine/parser/mod.rs` (mod) | Register noscript handling |
| `engine/render/elements.rs` (mod) | Add `render_select()`, `render_textarea()`, `render_form()` |
| `engine/render/page.rs` (mod) | Handle `<form>`, `<select>`, `<option>`, `<textarea>`, `<noscript>` in `process_element()` |
| `engine/render/context.rs` (mod) | Add `form_action: Option<String>`, `form_method: Option<String>` to `RenderContext` |
| `engine/form/mod.rs` (mod) | Wire form submission for rendered forms (existing Phase 4 infra) |

**Implementation details:**

1. **`<noscript>` as visible content:**
   - In the HTML parser, treat `<noscript>` like a `<div>` — parse its children normally
   - This is correct behavior for a no-JS browser: `<noscript>` content is shown when JS is disabled
   - In `process_element()`, don't consume `<noscript>` — let children render

2. **`<form>` tracking:**
   ```rust
   // In process_element:
   "form" => {
       ctx.form_action = get_attribute(node, "action");
       ctx.form_method = Some(get_attribute(node, "method").unwrap_or_else(|| String::from("GET")));
       false // don't consume — let children render
   }
   ```

3. **`<select>` rendering:**
   ```rust
   pub fn render_select(ctx: &mut RenderContext, node: &Node) {
       let name = get_attribute(node, "name").unwrap_or_default();
       // Find first <option> or selected option
       let selected = find_selected_option(node)
           .or_else(|| find_first_option(node))
           .unwrap_or_default();
       let width = ((selected.len() + 4) as u32) * ctx.char_width;
       ctx.current_line_elements.push(RenderElement {
           x: ctx.margin + ctx.current_x, width,
           content: RenderContent::Select { name, value: selected },
       });
       ctx.current_x += width + ctx.char_width;
   }
   ```

4. **`<textarea>` rendering:**
   ```rust
   pub fn render_textarea(ctx: &mut RenderContext, node: &Node) {
       let name = get_attribute(node, "name").unwrap_or_default();
       let cols: u32 = get_attribute(node, "cols").and_then(|c| c.parse().ok()).unwrap_or(40);
       let rows: u32 = get_attribute(node, "rows").and_then(|r| r.parse().ok()).unwrap_or(4);
       let width = cols * ctx.char_width;
       let height = rows * ctx.line_height;
       // Render as multi-line input box
       ctx.flush_line();
       ctx.lines.push(RenderLine {
           y: ctx.current_y,
           elements: alloc::vec![RenderElement {
               x: ctx.margin, width,
               content: RenderContent::Textarea { name, width, height },
           }],
       });
       ctx.current_y += height;
   }
   ```

5. **Submit via form action:**
   - `<input type="submit">` and `<button type="submit">` trigger navigation to `form.action`
   - Collect all `<input>` values in the current form context
   - Use Phase 4's form encoding (url-encode for GET, multipart for POST)

### Checklist

- [x] Treat `<noscript>` as visible content in HTML parser
- [x] Don't skip/consume `<noscript>` children in `process_element()`
- [x] Add `form_action`, `form_method` to `RenderContext`
- [x] Handle `<form>` open/close in `process_element()` and `handle_closing_tag()`
- [x] Add `render_select()` with name and selected option display
- [x] Add `render_textarea()` with multiline input box
- [x] Add `RenderContent::Select { name, value }` variant
- [x] Add `RenderContent::Textarea { name, width, height }` variant
- [x] Handle `<input type="submit">` as a submit button
- [x] Handle `<input type="hidden">` (store value, don't render)
- [x] Handle `<input type="text">` (existing, verify rendering)
- [x] Draw `Select` variant in graphics renderer
- [x] Draw `Textarea` variant in graphics renderer
- [x] Wire form submit action to navigation (POST/GET to form.action)
- [x] Tests: `<noscript>` content renders as visible
- [x] Tests: `<form>` with inputs renders all fields
- [x] Tests: `<select>` shows selected option
- [x] Tests: `<textarea>` renders with correct dimensions
- [x] Tests: hidden inputs are not displayed
- [x] Tests: form action/method passed to submission
- [x] Tests: Google-style noscript search form renders

---

### Sprint 2 Dependency Graph

```
Phase 6: Image Loading Pipeline
    │
    │   Uses: Phase 2 (HTTP pool), Phase 5 (JPEG decoder), existing PNG decoder
    │   Independent of Phase 7
    │
Phase 7: No-JS Forms & <noscript>
    │
    │   Uses: Phase 4 (form submission), existing HTML parser
    │   Independent of Phase 6
    │
 Both phases can proceed in parallel
```

### Sprint 2 Success Criteria

| Metric | Before | After |
|--------|--------|-------|
| Image display | `[IMG WxH]` placeholder | Actual decoded JPEG/PNG pixels |
| Google search form | Not visible | Renders via `<noscript>` fallback |
| `<select>` dropdowns | Ignored | Displayed with selected value |
| `<textarea>` fields | Ignored | Rendered as multiline input |
| Form submission from rendered page | Not possible | Works via form action URL |
