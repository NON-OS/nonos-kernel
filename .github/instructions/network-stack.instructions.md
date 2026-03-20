---
applyTo: "src/network/**,src/apps/ecosystem/browser/**"
---

# Network Stack — NONOS Kernel

## Architecture

```
Application Layer    src/apps/ecosystem/browser/     HTTP client, browser engine
                     src/network/stack/http/          HTTP parser
Privacy Layer        src/network/nym/                 NYM mixnet (anonymous routing)
                     src/network/onion/               Onion routing (Tor-like)
Transport Layer      src/network/stack/               TCP/UDP (smoltcp-based)
                     src/network/stack/async_ops/     Async TCP/DNS/HTTP operations
Security Layer       src/network/onion/tls/           TLS 1.3 (custom implementation)
                     src/network/firewall/            Stateful packet filter
Network Layer        src/network/stack/               IPv4/IPv6, ARP, ICMP
Link Layer           src/drivers/e1000/               Intel Gigabit NIC
                     src/drivers/rtl8139/             Realtek 10/100
                     src/drivers/rtl8168/             Realtek Gigabit
                     src/drivers/wifi/                Intel + Realtek WiFi
```

## Async Operations Pattern

The network stack is **non-blocking, poll-based**. No threads, no async runtime — just explicit state machines:

```rust
use crate::network::stack::async_ops::*;

// 1. Start operation (returns immediately)
tcp_start_connect(ip, port)?;

// 2. Poll until complete (called from main loop)
loop {
    match tcp_poll_connect() {
        AsyncResult::Pending => { /* yield, do other work */ }
        AsyncResult::Ready(conn_id) => { break; }
        AsyncResult::Error(e) => { return Err(e); }
    }
    crate::network::poll_network(); // Drive the TCP/IP stack
}

// 3. Send data
tcp_send(conn_id, &data)?;

// 4. Receive data (also poll-based)
match tcp_poll_receive(8192) {
    AsyncResult::Ready(bytes) => { /* process */ }
    AsyncResult::Pending => { /* wait */ }
    AsyncResult::Error(e) => { /* handle */ }
}
```

**Critical:** Call `crate::network::poll_network()` regularly. Without it, the TCP state machine doesn't advance — no ACKs, no retransmissions, no connection progress.

## TLS 1.3

Custom implementation in `src/network/onion/tls/`:

```rust
let mut tls = TLSConnection::new(host);
tls.start_handshake(tcp_conn_id)?;

// Poll handshake to completion
while !tls.is_handshake_complete() {
    tls.poll_handshake()?;
    poll_network();
}

// Send encrypted data
tls.send_application_data(http_request.as_bytes())?;

// Receive (returns decrypted plaintext)
match tls.poll_receive_response() {
    Ok(Some(plaintext)) => { /* process */ }
    Ok(None) => { /* pending */ }
    Err(e) => { /* TLS error */ }
}
```

### TLS Record Framing

TLS records have a 5-byte header: `[content_type(1), version(2), length(2)]`

```
+-------+-------+-------+-------+-------+------------------+
| CT    | 0x03  | 0x03  | len_h | len_l | payload[0..len]  |
+-------+-------+-------+-------+-------+------------------+
```

**Known bug:** TCP delivers arbitrary byte chunks. A single read may contain multiple complete records AND a partial record at the end. The partial bytes MUST be buffered and prepended to the next read. Failure to do so causes AEAD nonce desync. See `docs/BROWSER-RENDERING-IMPL.md` §1.1.

### AEAD Nonce Tracking

- Each direction (client→server, server→client) has an independent 64-bit sequence counter
- Nonce = XOR of the sequence counter with the IV derived during key schedule
- **The counter advances on every decrypt attempt** — failed decrypts still increment
- If a garbage record is fed to decrypt, the counter desyncs permanently

## DNS Resolution

```rust
use crate::network::stack::async_ops::{dns_start_query, dns_poll};

dns_start_query(hostname)?;

loop {
    match dns_poll() {
        AsyncResult::Ready(ip) => { break ip; }
        AsyncResult::Pending => { poll_network(); }
        AsyncResult::Error(e) => { return Err(e); }
    }
}
```

## HTTP Client

```rust
use crate::network::stack::http::parse::*;

// Build request
let request = format!(
    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    path, host
);

// Parse response
let (status, headers, body) = parse_http_response(&raw_response)?;
```

## Firewall

Stateful packet filter in `src/network/firewall/`:

- Default-deny inbound
- Allow established + related connections
- Rate limiting per source IP
- Capability-gated: only `Network` capability holders can modify rules

## Privacy Layers

| Layer | Location | Protocol |
|-------|----------|----------|
| NYM Mixnet | `network/nym/` | Anonymous packet routing via mix nodes |
| Onion | `network/onion/` | Tor-compatible circuit-based routing |
| SOCKS | `network/stack/socks/` | SOCKS4/5 proxy client |

Privacy features are capability-gated and feature-flagged.

## Driver Interface

NIC drivers expose a uniform interface:

```rust
pub trait NetworkDevice {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), DriverError>;
    fn receive_packet(&mut self) -> Option<Vec<u8>>;
    fn mac_address(&self) -> [u8; 6];
    fn link_up(&self) -> bool;
}
```

## Common Pitfalls

1. **Forgetting `poll_network()`** — TCP stack stalls, connections time out
2. **TLS record reassembly** — partial records across TCP reads cause nonce desync
3. **Timeout handling** — always set and check deadlines; hardware can hang
4. **DNS caching** — don't resolve the same hostname on every request
5. **Big allocations in packet handlers** — use bounded buffers, not unbounded `Vec`
6. **Redirect loops** — enforce max redirect count (currently 10)
