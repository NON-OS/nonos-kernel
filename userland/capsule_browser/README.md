# capsule_browser

## Role

`capsule_browser` is the graphical web browser capsule. It owns browser chrome,
navigation state, HTML and CSS parsing, layout, paint, the TLS 1.3 client, the
QuickJS bridge for page scripts, and the fetch machine for the user-facing
browser app. The handbook page is
[docs/handbook/apps/browser.md](../../docs/handbook/apps/browser.md).

```text
desktop shell
    |
    | launch app.browser
    v
browser -- MkIpc --> net.socks5 (Nym) | net.anon (Anyone) | net.sockets (Direct)
    |
    `-- MkSurface* --> compositor
```

## Microkernel contract

The browser is a user capsule. It does not own NIC hardware, routing tables,
DNS policy, kernel packet parsing, global input focus, or framebuffer memory.
It reaches the network through IPC services and presents pixels through the
graphics surface ABI.

- `MkServiceLookup` finds `net.sockets`, `net.dns`, `net.socks5` and
  `net.anon`; `MkIpcCallTimeout` carries every request and reply.
- `MkSurfaceCreate` and display-query authority are used for the app surface.
- The service endpoint is `service:4760:app.browser`, reply
  `reply:4761:endpoint.app.browser.reply`. Three more windows can open on the
  instance endpoints `app.browser.1` to `app.browser.3` (ports 4762 to 4767).

## Authority

`CAPSULE_REQUIRED_CAPS = 0x187d`: CoreExec, Network, IPC, Memory, Crypto,
FileSystem, GraphicsDisplayQuery and GraphicsSurfaceCreate. Network is what the network
services check before they serve it. Crypto is for the kernel randomness and
X25519 key the TLS handshake draws. FileSystem is for the vfs: bookmarks kept in
`/home/.browser/state.bin` and downloads saved to `/home/Downloads`. The browser
has no driver, device enumeration, MMIO, IRQ, DMA, PIO, admin, or debug authority.

The capsule is turned on by `nonos-capsule-browser` in
`microkernel-desktop-base`, so the standard desktop images carry it and the
offline desktop (`microkernel-desktop-offline`) does not.

## Network route

The browser starts on the system's default network from the policy store
(`Field::NetworkRoute`), or the Nym mixnet when the store holds none, and the
settings panel changes it for the next request. Nym goes through
`net.socks5`, Anyone through `net.anon`, Direct through `net.sockets` with
names asked of `net.dns`. When the chosen network's service is not running
the navigation fails and nothing is sent.

Each connection takes its way from its own host when it opens
(`src/browser/net/mixnet/way.rs`, by `nonos_route_link::for_host`): an
`.anyone` address goes through `net.anon` whatever the choice, or is refused
when `net.anon` is not running; everything an `.anyone` page asks for leaves
through Anyone, its clearnet images too; any other page's connections take
the reader's network. Direct is taken only on a page whose network is Direct
while the reader still has Direct chosen, and no refusal is ever answered by
going another way. A typed `.anyone` name is opened over plain http, the
onion circuit already encrypting it. The rule is held in
`capsule_browser_proofs` (`way_tests.rs`).

A call to a proxy waits at most 60 ms on the window's thread. Bytes for the
exit go in numbered frames; one the proxy has not answered is asked again,
unchanged, on later ticks while the fetch waits in its sending state, and the
proxy gives back the answer it kept, so they reach the exit once
(`net/mixnet/conv.rs`, `net/mixnet/pace.rs`). A close the proxy reports ends
a fetch in the step that sees it (`fetch/closed.rs`).

## Interface contract

The browser accepts keyboard and pointer events through the app skeleton,
classifies the address bar input as a URL, an `about:` page or a search,
fetches over HTTP/1.1 or HTTPS, parses the response, runs the page's scripts
in QuickJS-ng through `nonos_qjs`, lays the page out and paints it into its
compositor-owned surface.

## Privacy and persistence

Navigation state, history, TLS transcript material, response bytes, parsed
documents and `localStorage` live in capsule memory. The capsule does not
persist browsing history or write a cache, and it keeps no cookies. It does
not receive raw NIC frames, device registers, or kernel-global input state.

## Runtime lifecycle

The launcher starts the capsule with a 96 MiB heap. The browser creates a
surface, paints chrome, and waits for navigation input. A navigation has its
own fetch slot; stylesheets, scripts, images and fonts share a pool of up to
eight connections, six to one host, and four through a network's proxy, where
each is a stream of its own (frames naming a stream, `net/mixnet/streams.rs`)
and a finished one is kept for the next request to its host, skipping the
SOCKS handshake and the tunnel. Every wait is bounded by a budget: Nym's
longest, Anyone's half a minute of silence, direct shortest.

## Failure model

Bad URLs, DNS failure, connect failure, send failure, TLS certificate or
handshake failure, oversized responses, oversized TLS server flights,
malformed HTTP, redirect loops past five, decompression bombs and fetch
timeouts become explicit browser status states or an error page. They must
not panic the capsule or leave sockets open.

## What it does not do

- Scripts get no network: there is no `fetch`, `XMLHttpRequest` or
  `WebSocket`.
- No cookies, no persistent storage, no certificate revocation checks. The
  root set is the Mozilla set fixed at build time.
- ES modules run as classic scripts.
- No tabs; extra windows come from the instance endpoints.

## Tests

`userland/capsule_browser_proofs`, `userland/capsule_browser_html_proofs` and
`userland/browser_http_proofs` compile the capsule's own modules on the host.
The `harness` feature lets them build the render path without the syscall
runtime.
