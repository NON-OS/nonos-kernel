# Capability and Authority: enforcement audit

Scope: the syscall-boundary capability enforcement path, the per-syscall
requirement table, the `CapabilityToken` shape, and the `ambient` field
on `ProcessCapabilities`. The audit confirms what is structurally real,
flags what is broken in policy, and enumerates the dead surface that
needs to come out before substep 3.2 closes.

Verdicts: `OK`, `BROKEN`, `INERT`, `UNVERIFIED`.

---

## 1. Contract dispatch enforces a capability check on every syscall — **OK**

Every syscall dispatched by the contract goes through one entry, and
that entry resolves the capability before invoking the handler.

- `src/syscall/contract/dispatch.rs:32-37` — `dispatch(number, args)` is
  the single entry from per-arch shims. It calls `Capability::resolve`
  and short-circuits with `EPERM` if the resolution fails.
- `src/arch/x86_64/syscall/manager/entry.rs:73-89` — the x86_64 syscall
  asm shim's `syscall_handler` invokes `contract_dispatch` and nothing
  else. There is no second-class dispatch path.

A handler reached through `dispatch` has executable proof that the
capability check ran. A handler reached any other way does not exist on
the dispatched surface today.

---

## 2. `Capability::resolve` is the only path to a capability witness — **OK**

The witness is unforgeable in safe Rust.

- `src/syscall/contract/capability.rs:28-31` — `pub struct Capability {
  token: CapabilityToken }`. The `token` field is private to the
  `contract` module.
- `src/syscall/contract/capability.rs:42-50` — `Capability::resolve`
  is the only constructor. It returns `Some(Self { token })` only after
  `cap_table::is_allowed` returns `true`.
- Code outside `syscall/contract` cannot construct a `Capability`. A
  handler that takes a `Capability` argument therefore proves at the
  type level that the check ran.

---

## 3. Coverage of all 369 syscall numbers by the per-syscall table — **UNVERIFIED**

`SyscallNumber` defines roughly 369 enum variants
(`src/syscall/numbers/defs.rs`). The capability table lives at
`src/syscall/contract/cap_table/` and dispatches across twelve
per-domain files: `admin`, `crypto`, `debug`, `file_fs`, `hardware`,
`io_event`, `ipc`, `memory`, `network`, `process_sched`, `signal`,
`time`. Each file's `check` returns `Some(bool)` for numbers it
claims, `None` otherwise.

`src/syscall/contract/cap_table/mod.rs:34-53` walks the families in
order. A number not claimed by any family falls through to the wildcard
arm. **Whether every reachable `SyscallNumber` is claimed by some
family — and which ones drop into the wildcard — is not yet
enumerated.** A line-by-line cross-check between `SyscallNumber` and
the family `check` arms is the work of substep 3.3.

---

## 4. Wildcard fallback policy — **BROKEN**

`src/syscall/contract/cap_table/mod.rs:53` —
`.unwrap_or_else(|| caps.is_valid())`.

Any syscall number not claimed by any family is admitted on token
validity alone. The intent in the doc-comment above the function is
"the kernel's syscall surface still evolves and silent panics on
unrecognised numbers would be the wrong refusal mode," which is fair,
but the chosen fallback is the wrong direction. The honest fallback for
"unrecognised by the table" is **refuse**, not **admit on any valid
token**. A new syscall added to `SyscallNumber` should have to declare
its requirement explicitly before it becomes callable.

Substep 3.3 closes this: the table becomes total over `SyscallNumber`,
and the wildcard becomes `false` (or a hard panic in debug builds).

---

## 5. `CapabilityToken` predicates and granularity — **OK structurally, coarse**

`src/syscall/caps/checks.rs:19-108` defines twenty-one `can_*` helpers
on `CapabilityToken`. Each tests `self.grants(Capability::X) &&
self.is_valid()` for one of ten broad capability variants:

| Variant | Helpers backed by it |
|---|---|
| `CoreExec` | `can_exit`, `can_getpid`, `can_fork`, `can_exec`, `can_wait`, `can_signal` |
| `IO` | `can_read`, `can_write` |
| `FileSystem` | `can_open_files`, `can_close_files`, `can_stat`, `can_seek`, `can_modify_dirs`, `can_unlink` |
| `Memory` | `can_allocate_memory`, `can_deallocate_memory` |
| `Network` | `can_network` |
| `IPC` | `can_ipc` |
| `Crypto` | `can_crypto` |
| `Hardware` | `can_hardware` |
| `Debug` | `can_debug` |
| `Admin` | `can_admin` |

Granularity is broad-stroke. A capsule with `IO` can both read and
write any fd it already holds. A capsule with `FileSystem` can open,
close, stat, modify directories, and unlink. This is acceptable for the
current threat model because the `FileSystem` and `IO` capabilities
are themselves issued only at process spawn and the issuance audit
sits in Phase 4. Tightening the granularity (per-fd, per-mount,
per-path) is real future work and not in this phase.

`is_valid` itself goes through token signature + nonce + ttl checks
(`src/capabilities/token/types.rs:90`, signed by the kernel signing key
at mint via `crate::crypto::kernel_keys::sign_capability_token` —
`src/process/core/pcb_ops.rs:27`). Tokens are cryptographically bound
to the kernel; a forged token does not pass `is_valid`.

---

## 6. `ambient` bits on `ProcessCapabilities` — **INERT (dead surface)**

The `ambient` field is fully enumerated below.

**Definition (1 site):**
- `src/process/core/types.rs:114` — `pub ambient: u64` inside the
  `ProcessCapabilities` struct alongside `inheritable`, `permitted`,
  `effective`, `bounding`.

**Reads (1 site, reporting only):**
- `src/fs/procfs/pid/status.rs:66` — printed into `/proc/<pid>/status`
  as the `CapAmb:` line. Pure reporting; no authority decision is made
  on the value.

**Writes (0 sites):**
- `git grep "ambient *=\|ambient: "` returns only the type definition
  itself. No code path ever sets the field to anything other than its
  default of zero from `ProcessCapabilities::default()`.

**No enforcement reads:**
- The capability check at `contract::dispatch` consults
  `CapabilityToken`, which is built from `caps_bits: AtomicU64` on the
  PCB (`src/process/core/pcb_ops.rs:23`). The `caps_bits` field is
  separate from `ProcessCapabilities`. The `ProcessCapabilities` struct
  and its `ambient` member do not feed any check at the contract
  boundary.

**Verdict:** the `ambient` field has zero load-bearing semantics. It is
present on the type because the type was modeled after Linux's
five-set POSIX capability shape. Two clean options for substep 3.2:

1. **Remove the field outright.** Update procfs to print `0000000000000000`
   for the `CapAmb:` line (or omit it). The "no ambient bypass"
   architectural claim becomes source-true by construction.
2. **Keep the field but rename it to make the reporting-only nature
   explicit** (e.g. `ambient_reported: u64`) and document that nothing
   in the kernel grants authority through it.

Option 1 is cleaner and matches the project's "no decorative state"
discipline. Recommended.

---

## 7. `current_caps()` token source — **OK**

`src/syscall/caps/tokens.rs:21-24` — `current_caps()` looks up the
current process via `crate::process::current_process()` and calls
`.capability_token()` on it. The token is built from `pcb.caps_bits`
and signed at every call (`pcb_ops.rs:21-36`).

The signing-on-every-call pattern means `is_valid` will pass for any
token built from the same caps_bits bits via the same kernel signing
key, and a token whose bits are tampered after construction will fail
validation. The pattern is sound; whether per-call signing is the right
performance choice is a separate question outside this audit.

---

## 8. Stale `cap_table` entries for removed syscalls — **BROKEN-LITE**

Phase 2 step 3 removed `RtSigtimedwait`, `RtTgsigqueueinfo`, and
`Sigaltstack` from the dispatched surface. The cap_table entries for
those syscalls are still present:

- `src/syscall/contract/cap_table/signal.rs:24` — lists `RtSigtimedwait`
  and `Sigaltstack` in the `caps.is_valid()` arm.
- `src/syscall/contract/cap_table/signal.rs:35` — lists `RtTgsigqueueinfo`
  in the `caps.can_signal()` arm.

These entries are reachable (the cap check runs before the dispatcher's
domain router runs the wildcard ENOSYS), but they are dead in effect
because the handler returns ENOSYS regardless. Inconsistency, not
correctness bug. Cleaning these up belongs to substep 3.3 when the
table is rebuilt for totality.

---

## Summary

| # | Question | Verdict | Severity |
|---|---|---|---|
| 1 | Contract enforces capability check on every dispatch | OK | — |
| 2 | `Capability::resolve` is the only constructor | OK | — |
| 3 | Per-syscall coverage of all 369 numbers | UNVERIFIED | drives substep 3.3 |
| 4 | Wildcard fallback policy | BROKEN | high — admits unrecognised numbers on validity alone |
| 5 | Predicate granularity | OK structurally, coarse | acceptable for current phase |
| 6 | `ambient` field | INERT | dead surface; substep 3.2 removes |
| 7 | `current_caps` token source | OK | — |
| 8 | Stale cap_table entries for removed syscalls | BROKEN-LITE | cleaned in substep 3.3 |

Two real action items drive the remaining substeps:

- **3.2 (ambient resolution):** delete the `ambient` field from
  `ProcessCapabilities` and update the one procfs reader. The "no
  ambient bypass" claim becomes mechanical because the field does not
  exist.
- **3.3 + 3.4 (table totality + enforcement closure):** make the
  per-syscall table total over `SyscallNumber` (every number explicitly
  claimed), drop the stale entries from #8, and change the wildcard
  fallback from `caps.is_valid()` to refusal. After 3.4, a syscall
  that has not been deliberately admitted to the table is dispatched
  to a clean `EPERM`, not silently allowed.

The architectural shape of capability enforcement is sound. The two
real corrections are a dead field removal and a table-totality pass.
The remaining substeps (3.5 cap drop, 3.6 capsule manifest declaration)
build on the foundation those two close.
