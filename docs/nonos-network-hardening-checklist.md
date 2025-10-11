# Network Hardening Checklist 

Release: v0.2 Kernel 

## Base Stack (smoltcp)

- [ ] IPv4 config helper (ip/prefix/gateway) + static routes and neighbor cache APIs
- [ ] Bounded TCP send/recv with timeouts and backpressure
- [ ] HTTP/1.1 client: status check, content-length, caps (5 MiB), timeouts
- [ ] DNS (A) resolver: retry strategy, caps, timeouts
- [ ] NIC driver adapter: zero-copy paths where possible, stats, link notifications

## TLS

- [ ] Cert verifier backed by trust anchors, SAN/CN name check, EKU
- [ ] Override policy behind feature flag only; telemetry for policy bypass

## Mesh v1

- [ ] Noise IK authenticated handshake (Ed25519 identity mapped to X25519)
- [ ] HKDF labels; transcript binding; rekey schedule (time/traffic)
- [ ] ChaCha20-Poly1305 with 64-bit counters + 32-bit salt; replay window
- [ ] TLV wire v1 with version/cap-negotiation and strict bounds
- [ ] DV routing with split horizon + poisoned reverse; ETX metric; dampening; TTL
- [ ] Discovery via IPv6 multicast; v4 broadcast gated; NAT traversal (STUN/holes)
- [ ] Resource caps (peers/routes), per-peer rate limits, quotas, eviction
- [ ] Persistence of identity, peer cache, routes, replay windows
- [ ] Metrics and structured logs; health probes

## Testing/CI

- [ ] KATs: BLAKE3, AEAD, Noise transcripts
- [ ] Unit tests: replay windows, nonce counters, routing decisions
- [ ] Fuzzing: TLV decoder, route advertisements
- [ ] Integration: loopback + hardware NIC runs; onion path over the same stack

## Operations

- [ ] Config: knobs for caps, timeouts, NAT mode, discovery scope, trust anchors
- [ ] Secure defaults; documented override risks
