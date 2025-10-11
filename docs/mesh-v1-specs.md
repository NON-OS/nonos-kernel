# NØNOS Mesh v1 docs

Status: Stable 
Compatibility: Wire version 1 
Scope: Secure decentralized overlay for peer discovery, authenticated links, multi-hop routing and encrypted datagrams. Onion-friendly and resource-safe.

## 1. Identity and Keys

- Long-term identity: Ed25519 keypair (32-byte public).
- Link handshake: Noise IK pattern
  - Static initiator: Ed25519 (converted to X25519 using RFC 8032/Curve25519 key mapping).
  - Static responder: Ed25519 (converted similarly).
  - Ephemeral X25519 for forward secrecy.
- KDF: HKDF-SHA256 with domain labels:
  - "mesh-v1/ik/handshake"
  - "mesh-v1/traffic/tx"
  - "mesh-v1/traffic/rx"
  - "mesh-v1/rekey/ctx"
- Transcript binding: hash of Noise messages and capabilities TLV.

## 2. AEAD and Nonce Discipline

- AEAD: ChaCha20-Poly1305, 96-bit nonce, 16-byte tag.
- Nonce: 96-bit = salt(32 bits) || counter(64 bits).
  - Salt derived per session from HKDF with "mesh-v1/nonce-salt".
  - Counter monotonic per direction. Never reused. Wrap before reaching max (force rekey).
- Replay protection: sliding window of the last 4096 counters; reject stale or duplicate.

- Rekeying:
  - Periodic (time-based, default 1 hour) or traffic-based (at N packets or M bytes).
  - Rekey uses Noise rekey or HKDF-based key update with "mesh-v1/rekey/ctx::<epoch>".

## 3. Wire Format and TLV

- Versioned header:
  - magic: 0x4E 0x4F 0x4E 0x4F ('NONO')
  - version: 1
  - type: 1 byte (Beacon|Auth|RouteAdv|Data|Control)
  - flags: 1 byte
  - length: u16 (total TLVs length, not including header)
- TLV set (cap-negotiated):
  - 0x01 NodeId (32)
  - 0x02 PublicKey (Ed25519, 32)
  - 0x03 Capabilities (bitset)
  - 0x10 RouteEntry {dest: NodeId, metric: u32, seq: u64}
  - 0x11 RouteWithdraw {dest: NodeId, seq: u64}
  - 0x20 Data {dst: NodeId, ttl: u8, payload: bytes}
  - 0x30 NATInfo {reflexive addr/port, token}
  - 0x40 Signature (Ed25519 over header||TLVs)
- All messages length-prefixed; reject if exceeding policy caps (e.g., 8 KiB max).

## 4. Messages

- Beacon:
  - Purpose: discovery and liveness.
  - Contents: NodeId, PublicKey, Capabilities, optional NATInfo, Signature (over canonical TLVs).
  - Transport: IPv6 link-local multicast, IPv4 broadcast (if enabled).
  - Rate-limit: ≤ 1 per 3 seconds; jittered.

- Auth (Noise IK flight):
  - Sent on-demand to establish sessions; includes capabilities and endpoint hints.
  - Includes transcript hash TLV for binding.

- RouteAdv:
  - Distance-vector entries with split horizon + poisoned reverse.
  - Each entry: (dest, metric, seq). Higher seq is fresher; lower metric preferred.
  - Metric: ETX = f(loss, rtt); rtt via EWMA, loss via packet accounting.
  - Dampening: thresholds to suppress flapping.
  - Aging: expire entries after T (default 60 s) if not refreshed.

- Data:
  - Encrypted overlay datagrams addressed by NodeId with TTL.
  - Forwarding: next-hop from routing table; decrement TTL; drop on 0.
  - Queue caps and backpressure with per-peer quotas.

## 5. NAT Traversal & Reachability

- Discovery: prefer IPv6 link-local multicast; fallback to IPv4 broadcast if allowed.
- NAT traversal: STUN to learn reflexive addr/port; UDP hole punching where peers exchange candidates; relay bootstrap optional via configured rendezvous.

## 6. Resource & Abuse Controls

- Bounded tables: peers (default 4k), routes (default 16k).
- Per-peer rate limits: token buckets for ingress/egress; backoff on overuse.
- Proof-of-work (optional): challenge-response to throttle unsolicited floods.
- Admission policies: allowlists/denylists by key or prefix.

## 7. Persistence

- Identity keys: Ed25519 stored in secure vault.
- Peer cache: recent peers (id, pubkey, last endpoint, score).
- Routes: persisted to accelerate rejoin; stamp with age and seq.
- Replay windows and counters: persisted per session to survive restarts safely.

## 8. Observability

- Metrics: peers, routes, rtt EWMA, loss, tx/rx frames, decrypt failures, replays, drops, queue overflows.
- Structured logs with event codes and rate-limited error reporting.
- Health checks: loopback self-test, KATs, session liveness.

## 9. Security Considerations

- All beacons and adv must be signed; otherwise ignored.
- Unknown TLVs preserved when forwarding only if semantics safe; otherwise dropped.
- Canonical TLV ordering for signatures; accept out-of-order but normalize for verify.
- Reject overlong/duplicate TLVs; cap total message size.
- Constant-time signature verifies and AEAD tags; zeroization of key material.
