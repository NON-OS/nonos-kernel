# Capsule capability policy

Capabilities are the only way an app reaches kernel resources. The
kernel grants no ambient access. A capsule starts with the exact
mask the installer hands `MkSpawn`; that mask is bounded by the
manifest's `required_caps | optional_caps`.

```
   capsule  --syscall-->  syscall entry (gs:0x20 stack swap, swapgs)
                                |
                                v
                       +------------------+
                       | resolve caller   |   pid + caps from kernel
                       | pid + caps mask  |   process accounting
                       +------------------+
                                |
                                v
                       +------------------+
                       | cap_table check  |   per-family bit lookup
                       +------------------+
                                |
                       hit  ----+---- miss
                       |               |
                       v               v
                   handler          EPERM
```

## 1. Capability set

The mask is a `u64`. Each bit is a named capability. Names are
defined in `crate::syscall::caps`. The current set:

| Bit | Name | What it grants |
|---|---|---|
| 0 | `CAP_IPC` | call `MkIpcSend` / `MkIpcRecv` / `MkIpcCall` |
| 1 | `CAP_MEMORY` | call `MkMmap` / `MkMunmap` for the capsule's own AS |
| 2 | `CAP_VFS` | open an endpoint connection to the VFS capsule |
| 3 | `CAP_NETWORK` | open an endpoint connection to a network capsule |
| 4 | `CAP_DISPLAY` | open an endpoint connection to a display capsule |
| 5 | `CAP_INPUT` | receive input events from an input capsule |
| 6 | `CAP_CRYPTO` | open an endpoint connection to the crypto capsule |
| 7 | `CAP_ENTROPY` | open an endpoint connection to the entropy capsule |
| 8 | `CAP_WALLET_VIEW` | read wallet identity / public address |
| 9 | `CAP_WALLET_SPEND` | request a wallet authorisation signature |
| 10 | `CAP_PERSISTENCE` | install with `storage_policy = persistent` |
| 11 | `CAP_UPDATE` | accept update notifications from `capsule_update` |
| 12 | `CAP_HARDWARE_BROKER` | open an endpoint connection to the hardware broker |

Bits 13..63 are reserved.

`CAP_WALLET_VIEW` and `CAP_WALLET_SPEND` are deliberately split: an
app that displays balance (`view`) is different from an app that
can request the user to sign a payment (`spend`).

## 2. Manifest declarations

A manifest declares two masks:

- `required_caps`: granted unconditionally at install time.
- `optional_caps`: the user may opt in or out per cap, per install.

The two masks must be disjoint. The verifier rejects overlap.

## 3. Grant rule

At spawn time the installer passes `granted_caps` to `MkSpawn`. The
kernel's manifest verifier rejects `granted_caps & !(required |
optional) != 0`. The installer is the only entity that can compose
`granted_caps`; capsules cannot ask for caps post-spawn.

## 4. Authority

Capability checks always read pid and caps from kernel-side process
accounting, never from an IPC payload. A capsule cannot lie about
its own caps; the kernel-side IPC handler reads the caller pid out
of the syscall frame and looks the caps up.

## 5. No ambient access

- No ambient filesystem. A capsule reaches files only through the
  VFS capsule, gated by `CAP_VFS`.
- No ambient network. A capsule reaches sockets only through a
  network capsule, gated by `CAP_NETWORK`.
- No ambient persistence. State dies on capsule exit unless
  `CAP_PERSISTENCE` is granted and the capsule routes through the
  persistence store.
- No ambient hardware. Direct port I/O, MMIO, or DMA is reserved
  for the kernel's trusted-path drivers; capsules go through the
  hardware broker capsule when `CAP_HARDWARE_BROKER` is granted.
- No ambient wallet. An app never sees private keys; it requests
  a signature through `capsule_wallet` and gets an authorisation
  receipt.

## 6. Endpoint grants

A capsule's manifest lists IPC endpoints it intends to register
(server-side). The kernel grants each endpoint at spawn:

```
for ep in manifest.endpoints:
    MkCapGrant(pid, EndpointOwner(ep.name))
```

Endpoint *callers* (clients) need a separate grant; the
installer hands the new capsule a `ConnectTo(target_endpoint)`
grant for every dependency the user approved. There is no global
endpoint table; every connection is an explicit grant.

## 7. Revocation

`MkCapRevoke(pid, cap)` immediately invalidates the cap. Pending
syscalls that read the cap fail with `EPERM`. The installer revokes
caps when the capsule exits or is uninstalled. Revocation is not
delayed; there is no grace period.

## 8. Failure mode

A `CapCheck` that fails returns `EPERM`. No partial result. No
"degraded mode". A capsule denied `CAP_NETWORK` cannot reach the
network indirectly through another capsule unless the user
explicitly authorised that connection; the broker capsules check
the caller's caps before bridging.

## 9. What the user sees

At install the user sees two lists:

- "this app needs" → `required_caps`
- "this app would like" → `optional_caps`

A user can install with `required_caps` only. The app must handle
the absence of optional caps without crashing.

## 10. Static gate

`tools/ci/run-static-checks.sh` rejects any kernel module that
imports a marketplace cap or wallet cap directly; those names live
in `services::caps` for the userland-facing surface, and the kernel
itself only knows the bit numbers.
