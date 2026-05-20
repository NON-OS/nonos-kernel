# capsule_net_nym

## Role

`capsule_net_nym` is the privacy mixer capsule for outbound traffic. It sits
above `capsule_net_udp` and below user network capsules that opt into
mix-routed delivery. Its responsibility is narrow: bind to the chosen mix
chain, wrap an application datagram in successive layered envelopes, and
hand the outermost envelope to the UDP capsule for first-hop transport.

```text
  user capsule
       |
       | clear payload + chain id
       v
  net.nym  ---- layered envelopes / per-hop AEAD ----+
       |                                              |
       | OP_BIND_CHAIN / OP_ROTATE_EPOCH              |
       v                                              v
  chain directory (post-beta)                       net.udp -> net.ip -> net.l2
```

## Microkernel contract

The capsule has no hardware grants. It is an IPC service:

- `MkIpcRecv` receives requests on `service:4500:net.nym`.
- `MkIpcSend` replies through `reply:4501:endpoint.4294967330`.
- Its wire magic is `NNYM`.
- Its endpoint name is `net.nym`.

## Interface contract

| Op | Direction | Body | Reply |
|---|---|---|---|
| `OP_HEALTHCHECK` | request | empty | status only |
| `OP_SEND_MIX` | request | u32 payload_len + payload | status; `E_NOTSUP` in beta |
| `OP_BIND_CHAIN` | request | u32 hops + per-hop pubkeys | status; `E_NOTSUP` in beta |
| `OP_ROTATE_EPOCH` | request | empty | status; `E_NOTSUP` in beta |

## Authority

The manifest capability mask is `CAPSULE_REQUIRED_CAPS := 0x10` (`IPC`
only). No `Driver`, `Mmio`, `Dma`, `Irq`, or `Pio` is requested. The
capsule cannot touch hardware directly. Calls cross `MkIpcRecv` and
`MkIpcSend` only.

## Privacy and persistence

RAM-only. The capsule keeps per-epoch chain state, hop pubkeys, and a small
ring of in-flight envelopes in heap memory. Nothing is written to disk;
nothing survives a reboot.

## Runtime lifecycle

1. `_start` runs `heap_init` and enters `server::run`.
2. The server registers `net.nym` and waits for `OP_BIND_CHAIN`.
3. Until a chain is bound, every `OP_SEND_MIX` returns `E_NOTREADY`.
4. On `OP_BIND_CHAIN`, per-hop pubkeys are validated and stored.
5. On `OP_SEND_MIX`, the payload is wrapped per hop and handed to `net.udp`.

## Failure model

Every op returns an explicit POSIX errno on failure. There is no silent
success and no fallback that would deliver an unmixed datagram. A bind
failure leaves the chain unbound; a send before bind returns `E_NOTREADY`.

## Current implemented surface

- `OP_HEALTHCHECK` returns `0`.
- `OP_SEND_MIX`, `OP_BIND_CHAIN`, `OP_ROTATE_EPOCH` return `E_NOTSUP` until
  the live wrap pipeline lands.

## Wire format

NCMP envelope:

```
magic = b"NNYM"
version = 1
op = u16
flags = u16
seq = u32
payload_len = u32
payload bytes...
```

Reply payload is `i32 errno` followed by per-op body bytes.

## State ownership

- per-epoch chain table: hop pubkeys + per-hop epoch counter
- in-flight ring: bounded queue of envelopes pending UDP submission
- handshake state: BIND outcomes per caller pid

No state is shared across capsules; nothing leaks into the kernel.

## Operating rules

- Never accept a payload larger than `MAX_MIX_PAYLOAD`.
- Never bind a chain shorter than 3 hops or longer than 8.
- Never reuse an envelope key across epochs.
- Never log payload bytes; only sizes and per-hop counters.

## Release target

Beta: scaffolding only. Live wrap + chain discovery target post-beta in
`v0.9.1`. The manifest is signed under the production trust chain so the
capsule can be spawned with the rest of the network fleet.

## Release evidence

- `cargo check --target ../x86_64-nonos-user.json` is green.
- The capsule manifest matches the embedded ELF payload hash in
  `nonos-data/trust/MANIFEST.sha256`.

## Release checklist

- [x] Capsule.mk pins the namespace, slug, endpoints, and capability mask.
- [x] `README.md` documents the contract.
- [x] The capsule replies with `E_NOTSUP` on operational ops until the
      live pipeline lands.
- [ ] Live mix wrap pipeline (post-beta).
- [ ] Chain directory service (post-beta).

## Explicit non-goals today

- No mix directory service in this capsule; chains come pre-bound.
- No traffic shaping or cover traffic in beta.
- No replay protection beyond per-hop epoch counters.

## Verification

```
cd userland/capsule_net_nym
cargo check --target ../x86_64-nonos-user.json \
  -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
```
