# 00 — Golden ABI Equivalence Table: BootHandoffV1 (producer ↔ consumer)

Read-only audit. Branch `feature/bootloader-hardening`. Every offset/size below is
derived from the `#[repr(C)]` placement algorithm, not eyeballed:

> Fields are placed in declaration order. Each field starts at the next offset that
> is a multiple of its own alignment (padding inserted as needed). The struct's
> alignment is the maximum alignment of its members. The struct's size is the final
> field end rounded up to a multiple of the struct alignment (trailing padding).

Target: `x86_64-nonos` (`.cargo/config.toml:1`) → `u64`/`usize`/pointer = 8 bytes,
align 8; `u32` = 4/4; `u16` = 2/2; `u8` = 1/1; `[u8; N]` = N bytes, align 1;
`#[repr(u8)]` field-less enum = 1 byte, align 1 (independent of variant count).

## Type resolution (both sides, `path:line`)

| Logical type | Producer definition | Consumer definition |
|---|---|---|
| `BootHandoffV1` | `nonos-bootloader/src/handoff/types/handoff.rs:28` `#[repr(C)]` (`:26`) | `src/boot/handoff/types/handoff.rs:28` `#[repr(C)]` (`:26`) |
| `FramebufferInfo` | `nonos-bootloader/src/handoff/types/framebuffer.rs:20` `#[repr(C)]` (`:18`) | `src/boot/handoff/types/framebuffer.rs:21` `#[repr(C)]` (`:19`) |
| `MemoryMap` | `nonos-bootloader/src/handoff/types/memory.rs:20` `#[repr(C)]` (`:18`) | `src/boot/handoff/types/memory.rs:53` `#[repr(C)]` (`:51`) |
| `AcpiInfo` | `nonos-bootloader/src/handoff/types/system.rs:20` `#[repr(C)]` (`:18`) | `src/boot/handoff/types/info.rs:19` `#[repr(C)]` (`:17`) |
| `SmbiosInfo` | `nonos-bootloader/src/handoff/types/system.rs:27` `#[repr(C)]` (`:25`) | `src/boot/handoff/types/info.rs:25` `#[repr(C)]` (`:23`) |
| `Modules` | `nonos-bootloader/src/handoff/types/system.rs:34` `#[repr(C)]` (`:32`) | `src/boot/handoff/types/info.rs:40` `#[repr(C)]` (`:38`) |
| `Timing` | `nonos-bootloader/src/handoff/types/system.rs:43` `#[repr(C)]` (`:41`) | `src/boot/handoff/types/info.rs:60` `#[repr(C)]` (`:58`) |
| `Measurements` | `nonos-bootloader/src/handoff/types/security.rs:20` `#[repr(C)]` (`:18`) | `src/boot/handoff/types/security.rs:19` `#[repr(C)]` (`:17`) |
| `RngSeed` | `nonos-bootloader/src/handoff/types/security.rs:42` `#[repr(C)]` (`:40`) | `src/boot/handoff/types/security.rs:63` `#[repr(C)]` (`:61`) |
| `ZkAttestation` | `nonos-bootloader/src/handoff/types/security.rs:31` `#[repr(C)]` (`:29`) | `src/boot/handoff/types/security.rs:41` `#[repr(C)]` (`:39`) |
| `FirmwareHandoff` | `crate::firmware::FirmwareHandoff` → re-export `nonos-bootloader/src/firmware/mod.rs:36` → `nonos-bootloader/src/firmware/types.rs:43` `#[repr(C)]` (`:41`) | `src/boot/handoff/types/firmware.rs:94` `#[repr(C)]` (`:92`) |
| `FirmwareEntry` (nested) | `nonos-bootloader/src/firmware/types.rs:37` `#[repr(C)]` (`:35`) | `src/boot/handoff/types/firmware.rs:73` `#[repr(C)]` (`:71`) |
| `FirmwareType` (nested) | `nonos-bootloader/src/firmware/types.rs:21` `#[repr(u8)]` (`:19`) | `src/boot/handoff/types/firmware.rs:21` `#[repr(u8)]` (`:19`) |

Producer `crate::firmware::FirmwareHandoff` resolution chain confirmed:
`nonos-bootloader/src/handoff/types/handoff.rs:23` `use crate::firmware::FirmwareHandoff;`
→ `nonos-bootloader/src/firmware/mod.rs:36` `pub use types::{FirmwareEntry, FirmwareHandoff, FirmwareType, MAX_FIRMWARE_ENTRIES};`
→ real definition `nonos-bootloader/src/firmware/types.rs:43`. Recursed into both
nested sub-types (`FirmwareEntry`, `FirmwareType`); tabled below.

Pointed-to (not embedded) array element types — ABI-relevant where the consumer
dereferences producer-written arrays, but they do NOT affect `BootHandoffV1`
size/layout because the struct holds only raw `u64` pointers/counts:
`MemoryMapEntry` producer `nonos-bootloader/src/handoff/jump/types.rs:20` vs
consumer `src/boot/handoff/types/memory.rs:42`; consumer also defines `Module`
`src/boot/handoff/types/info.rs:31` with no producer counterpart (producer
`Modules.ptr` is populated elsewhere; element layout out of scope of this table
but flagged as a follow-up surface). These are noted, not scored, in the summary.

`nonos-bootloader/src/handoff/types/crypto.rs:19` `CryptoHandoff` was inspected
for relevance: it is NOT `#[repr(C)]`, uses `bool` fields, and is NOT referenced
by `BootHandoffV1` (handoff.rs imports `Measurements/RngSeed/ZkAttestation` from
`security.rs`, never from `crypto.rs`). Out of the handoff ABI; excluded from
scoring.

---

## Step 2 — Per-struct layout tables (derived offsets/sizes)

Notation: `off` = byte offset of the field; `sz` = byte size of the field's type;
`pad→N` marks alignment padding bytes inserted before that field.

### FramebufferInfo  (producer & consumer fields identical; align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| ptr | u64 | 0 | 8 | 0 | 8 | MATCH |
| size | u64 | 8 | 8 | 8 | 8 | MATCH |
| width | u32 | 16 | 4 | 16 | 4 | MATCH |
| height | u32 | 20 | 4 | 20 | 4 | MATCH |
| stride | u32 | 24 | 4 | 24 | 4 | MATCH |
| pixel_format | u32 | 28 | 4 | 28 | 4 | MATCH |
| cursor_y | u32 | 32 | 4 | 32 | 4 | MATCH |
| reserved | u32 | 36 | 4 | 36 | 4 | MATCH |
| **struct** | | **size 40, align 8** | | **size 40, align 8** | | **MATCH** |

End of last field = 40; 40 % 8 = 0 → no trailing pad. Consumer derives `Default`;
producer does not. Derive macros do not change `#[repr(C)]` layout → no effect.

### MemoryMap  (producer & consumer fields identical; align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| ptr | u64 | 0 | 8 | 0 | 8 | MATCH |
| entry_size | u32 | 8 | 4 | 8 | 4 | MATCH |
| entry_count | u32 | 12 | 4 | 12 | 4 | MATCH |
| desc_version | u32 | 16 | 4 | 16 | 4 | MATCH |
| **struct** | | **size 24, align 8** | | **size 24, align 8** | | **MATCH** |

Last field ends at 20; struct align 8 → trailing pad 4 → size 24, both sides.

### AcpiInfo / SmbiosInfo  (single u64 each; align 8)

| logical | field | type | prod off/sz | cons off/sz | verdict |
|---|---|---|---|---|---|
| AcpiInfo | rsdp | u64 | 0 / 8 | 0 / 8 | MATCH |
| AcpiInfo | **struct** | | **8, align 8** | **8, align 8** | **MATCH** |
| SmbiosInfo | entry | u64 | 0 / 8 | 0 / 8 | MATCH |
| SmbiosInfo | **struct** | | **8, align 8** | **8, align 8** | **MATCH** |

### Modules  (producer & consumer fields identical; align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| ptr | u64 | 0 | 8 | 0 | 8 | MATCH |
| count | u32 | 8 | 4 | 8 | 4 | MATCH |
| reserved | u32 | 12 | 4 | 12 | 4 | MATCH |
| **struct** | | **size 16, align 8** | | **size 16, align 8** | | **MATCH** |

### Timing  (producer & consumer fields identical; align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| tsc_hz | u64 | 0 | 8 | 0 | 8 | MATCH |
| unix_epoch_ms | u64 | 8 | 8 | 8 | 8 | MATCH |
| **struct** | | **size 16, align 8** | | **size 16, align 8** | | **MATCH** |

### Measurements  (producer & consumer fields identical; align 1)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| kernel_blake3 | [u8; 32] | 0 | 32 | 0 | 32 | MATCH |
| kernel_sig_ok | u8 | 32 | 1 | 32 | 1 | MATCH |
| secure_boot | u8 | 33 | 1 | 33 | 1 | MATCH |
| zk_attestation_ok | u8 | 34 | 1 | 34 | 1 | MATCH |
| reserved | [u8; 5] | 35 | 5 | 35 | 5 | MATCH |
| **struct** | | **size 40, align 1** | | **size 40, align 1** | | **MATCH** |

All members align 1 → no internal/trailing padding; size = 40.

### RngSeed  (single [u8; 32]; align 1)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| seed32 | [u8; 32] | 0 | 32 | 0 | 32 | MATCH |
| **struct** | | **size 32, align 1** | | **size 32, align 1** | | **MATCH** |

### ZkAttestation  (producer & consumer fields identical; align 1)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| verified | u8 | 0 | 1 | 0 | 1 | MATCH |
| flags | u8 | 1 | 1 | 1 | 1 | MATCH |
| reserved | [u8; 6] | 2 | 6 | 2 | 6 | MATCH |
| program_hash | [u8; 32] | 8 | 32 | 8 | 32 | MATCH |
| capsule_commitment | [u8; 32] | 40 | 32 | 40 | 32 | MATCH |
| **struct** | | **size 72, align 1** | | **size 72, align 1** | | **MATCH** |

All members align 1 → no padding; size = 72.

### FirmwareType  (`#[repr(u8)]`, field-less; nested in FirmwareEntry)

`#[repr(u8)]` fixes size = 1, align = 1 regardless of variant count. Producer
variant set `nonos-bootloader/src/firmware/types.rs:22-30` (45 variants,
`Unknown=0` … `QualcommQca6174=114`); consumer `src/boot/handoff/types/firmware.rs:22-68`
(same 45 explicit discriminants, same names, same values; consumer adds
`#[default]` attribute + derives `Default` — attribute does not alter `#[repr(u8)]`
layout). Discriminant value set is byte-for-byte equal.

| property | producer | consumer | verdict |
|---|---|---|---|
| repr | `#[repr(u8)]` | `#[repr(u8)]` | MATCH |
| size / align | 1 / 1 | 1 / 1 | MATCH |
| discriminant value set | 0,1..10,20..29,40,41,50,51,60,61,70..73,80,81,90..92,100..104,110..114 | identical | MATCH |

### FirmwareEntry  (nested element of FirmwareHandoff.entries; align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| fw_type | FirmwareType (u8) | 0 | 1 | 0 | 1 | MATCH |
| (pad→8) | — | 1..8 | 7 | 1..8 | 7 | MATCH |
| ptr | u64 | 8 | 8 | 8 | 8 | MATCH |
| size | u32 | 16 | 4 | 16 | 4 | MATCH |
| reserved | u32 | 20 | 4 | 20 | 4 | MATCH |
| **struct** | | **size 24, align 8** | | **size 24, align 8** | | **MATCH** |

`fw_type` (align 1) at 0; `ptr` needs align 8 → 7 pad bytes (offsets 1..8); last
field ends at 24; 24 % 8 = 0 → no trailing pad. Size 24 both sides.

### FirmwareHandoff  (align 8)

| field | type | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| count | usize | 0 | 8 | 0 | 8 | MATCH |
| entries | [FirmwareEntry; 64] | 8 | 1536 | 8 | 1536 | MATCH |
| **struct** | | **size 1544, align 8** | | **size 1544, align 8** | | **MATCH** |

`MAX_FIRMWARE_ENTRIES = 64` both sides (`nonos-bootloader/src/firmware/types.rs:17`,
`src/boot/handoff/types/firmware.rs:17`). Array size = 24 × 64 = 1536; element
align 8; struct end = 8 + 1536 = 1544; 1544 % 8 = 0 → no trailing pad.

### BootHandoffV1  (top-level; align 8 = max member align)

Field order confirmed identical both sides (producer
`nonos-bootloader/src/handoff/types/handoff.rs:28`, consumer
`src/boot/handoff/types/handoff.rs:28-45`). Offsets derived using the leaf sizes
proven above.

| field | type (align, size) | prod off | prod sz | cons off | cons sz | verdict |
|---|---|---|---|---|---|---|
| magic | u32 (4, 4) | 0 | 4 | 0 | 4 | MATCH |
| version | u16 (2, 2) | 4 | 2 | 4 | 2 | MATCH |
| size | u16 (2, 2) | 6 | 2 | 6 | 2 | MATCH |
| flags | u64 (8, 8) | 8 | 8 | 8 | 8 | MATCH |
| entry_point | u64 (8, 8) | 16 | 8 | 16 | 8 | MATCH |
| fb | FramebufferInfo (8, 40) | 24 | 40 | 24 | 40 | MATCH |
| mmap | MemoryMap (8, 24) | 64 | 24 | 64 | 24 | MATCH |
| acpi | AcpiInfo (8, 8) | 88 | 8 | 88 | 8 | MATCH |
| smbios | SmbiosInfo (8, 8) | 96 | 8 | 96 | 8 | MATCH |
| modules | Modules (8, 16) | 104 | 16 | 104 | 16 | MATCH |
| timing | Timing (8, 16) | 120 | 16 | 120 | 16 | MATCH |
| meas | Measurements (1, 40) | 136 | 40 | 136 | 40 | MATCH |
| rng | RngSeed (1, 32) | 176 | 32 | 176 | 32 | MATCH |
| zk | ZkAttestation (1, 72) | 208 | 72 | 208 | 72 | MATCH |
| firmware | FirmwareHandoff (8, 1544) | 280 | 1544 | 280 | 1544 | MATCH |
| cmdline_ptr | u64 (8, 8) | 1824 | 8 | 1824 | 8 | MATCH |
| **struct** | | **size 1832, align 8** | | **size 1832, align 8** | | **MATCH** |

Derivation notes:
- `magic@0` (sz4) → `version` align 2 at 4 → `size` align 2 at 6 → next free 8.
- `flags` align 8: 8 already aligned, no pad. `entry_point@16`.
- `fb` align 8 @24, size 40 → next free 64. `mmap@64` sz24 → 88. `acpi@88` sz8 → 96.
  `smbios@96` sz8 → 104. `modules@104` sz16 → 120. `timing@120` sz16 → 136.
- `meas` align 1 @136 sz40 → 176. `rng` align 1 @176 sz32 → 208.
  `zk` align 1 @208 sz72 → 280.
- `firmware` align 8: 280 % 8 = 0, no pad, @280 sz1544 → 1824.
- `cmdline_ptr` align 8 @1824 sz8 → 1832. Struct align 8; 1832 % 8 = 0 → no
  trailing pad. **Total size 1832, both sides.**

`size_of::<Self>()` is therefore 1832 on both sides; both `is_valid()` checks
`self.size as usize == size_of::<Self>()` agree on the 1832 expectation.

---

## Step 3 — Constants & flag bits

| symbol | producer | producer cite | consumer | consumer cite | verdict |
|---|---|---|---|---|---|
| `HANDOFF_MAGIC` | `0x4E_4F_4E_4F` (u32) | `nonos-bootloader/src/handoff/types/constants.rs:17` | `0x4E_4F_4E_4F` (u32) | `src/boot/handoff/types/constants.rs:17` | MATCH |
| `HANDOFF_VERSION` | `1` (u16) | `nonos-bootloader/src/handoff/types/constants.rs:18` | `1` (u16) | `src/boot/handoff/types/constants.rs:18` | MATCH |
| `MAX_CMDLINE_LEN` | **NO PRODUCER SYMBOL** | (absent — `grep` of `nonos-bootloader/src/handoff/` finds none) | `4096` (usize) | `src/boot/handoff/types/constants.rs:19` | **DRIFT (S2)** |
| `flags::WX` | `1 << 0` | `…/constants.rs:21` | `1 << 0` | `…/constants.rs:34` | MATCH |
| `flags::NXE` | `1 << 1` | `…/constants.rs:22` | `1 << 1` | `…/constants.rs:35` | MATCH |
| `flags::SMEP` | `1 << 2` | `…/constants.rs:23` | `1 << 2` | `…/constants.rs:36` | MATCH |
| `flags::SMAP` | `1 << 3` | `…/constants.rs:24` | `1 << 3` | `…/constants.rs:37` | MATCH |
| `flags::UMIP` | `1 << 4` | `…/constants.rs:25` | `1 << 4` | `…/constants.rs:38` | MATCH |
| `flags::IDMAP_PRESERVED` | `1 << 5` | `…/constants.rs:26` | `1 << 5` | `…/constants.rs:39` | MATCH |
| `flags::FB_AVAILABLE` | `1 << 6` | `…/constants.rs:27` | `1 << 6` | `…/constants.rs:40` | MATCH |
| `flags::ACPI_AVAILABLE` | `1 << 7` | `…/constants.rs:28` | `1 << 7` | `…/constants.rs:41` | MATCH |
| `flags::TPM_MEASURED` | `1 << 8` | `…/constants.rs:29` | `1 << 8` | `…/constants.rs:42` | MATCH |
| `flags::SECURE_BOOT` | `1 << 9` | `…/constants.rs:30` | `1 << 9` | `…/constants.rs:43` | MATCH |
| `flags::ZK_ATTESTED` | `1 << 10` | `…/constants.rs:31` | `1 << 10` | `…/constants.rs:44` | MATCH |
| `pixel_format::{RGB,BGR,RGBX,BGRX}` | **NO PRODUCER SYMBOL** | (absent in producer `constants.rs`) | `0,1,2,3` (u32) | `src/boot/handoff/types/constants.rs:54-57` | DRIFT (S3) — see note |

`MAX_CMDLINE_LEN` DRIFT, severity **S2 (weakened guarantee / unbounded read)**:
the producer cmdline writer `nonos-bootloader/src/handoff/prepare/cmdline.rs:20`
allocates `s.len()+1` rounded to pages and `copy_nonoverlapping`s the full string
with **no cap** — it can emit an arbitrarily long NUL-terminated cmdline. The
consumer `cmdline()` (`src/boot/handoff/types/handoff.rs:78-111`) scans only up to
`MAX_CMDLINE_LEN = 4096` and silently truncates beyond that (loop bound
`while len < MAX_CMDLINE_LEN`). The cap the consumer assumes is an invariant the
producer never enforces and cannot enforce (it has no such symbol). Result: a
producer-supplied cmdline > 4096 bytes is silently truncated by the kernel — a
silent contract divergence, not a layout drift, but a real ABI-contract drift.

`pixel_format::*` DRIFT, severity **S3 (correctness/encoding agreement)**: the
producer has no symbolic pixel-format enumeration in `constants.rs`; the
`FramebufferInfo.pixel_format: u32` value the producer writes is governed by code
outside the audited type modules. The consumer hard-codes `RGB=0,BGR=1,RGBX=2,
BGRX=3` and `bytes_per_pixel()` (`src/boot/handoff/types/framebuffer.rs:39-45`)
depends on that mapping. Whether the producer's emitted integers agree is
UNVERIFIED from the type modules alone; flagged as a follow-up surface, scored
DRIFT because the consumer assumes a numbering the producer's type layer does not
declare.

---

## Step 4 — `is_valid()` divergence (authoritative-invariant analysis)

| check | producer `is_valid()` (`nonos-bootloader/src/handoff/types/handoff.rs:32-40`) | consumer `is_valid()` (`src/boot/handoff/types/handoff.rs:49-53`) | verdict |
|---|---|---|---|
| `magic == HANDOFF_MAGIC` | yes (`:33`) | yes (`:50`) | MATCH |
| `version == HANDOFF_VERSION` | yes (`:34`) | yes (`:51`) | MATCH |
| `size as usize == size_of::<Self>()` | yes (`:35`) | yes (`:52`) | MATCH (both expect 1832) |
| `entry_point != 0` | **yes (`:36`)** | **NOT CHECKED** | **DRIFT (S1)** |
| `mmap.entry_count > 0 ⇒ mmap.ptr != 0` | **yes (`:37`)** | **NOT CHECKED** | **DRIFT (S1)** |
| `mmap.entry_count > 0 ⇒ mmap.entry_size != 0` | **yes (`:38`)** | **NOT CHECKED** | **DRIFT (S1)** |

Severity **S1 (exploitable trust bypass / weaker consumer gate)**. The trust
boundary direction is producer → consumer; the consumer is the party that must
*defend* against a malformed/hostile handoff. Today the consumer validates a
strict subset of the producer's invariants: a handoff with `entry_point == 0`, or
with `entry_count > 0` but `ptr == 0` / `entry_size == 0`, passes the consumer's
`is_valid()` and is then dereferenced — `MemoryMap::entries()`
(`src/boot/handoff/types/memory.rs:62-72`) builds a slice from `self.ptr` and
`self.entry_count`. If `ptr == 0` with `entry_count > 0` this is a null/garbage
slice the consumer's own validator did not reject; the producer's validator would
have. The consumer trusting a weaker gate than the producer enforces is the
classic confused-deputy: validation strength must be monotonic in the direction
of decreasing trust.

### Authoritative-invariant recommendation (recommendation only — NOT implemented)

1. The consumer's `is_valid()` MUST be a superset of the producer's invariants
   (consumer enforces ≥ producer). Minimum remediation: add `entry_point != 0`
   and the two `mmap` consistency checks to
   `src/boot/handoff/types/handoff.rs:is_valid`, plus a `cmdline` length bound at
   read time that does not silently truncate (reject, or surface truncation).
2. The structural root cause is that `BootHandoffV1` and every nested type are
   **independently re-declared in two crates** with no shared definition. Layout
   parity today is coincidental, not enforced — a one-line edit on either side
   (e.g. reordering `meas`/`rng`, changing a `reserved` width, adding a
   `FirmwareType` variant past a `#[repr(u8)]` boundary, flipping `usize`) drifts
   the ABI with no compiler error and no test catching it (an S0 unbootable /
   silent-trust-compromise condition). The fix is to extract ONE
   `#[repr(C)]` definition both crates import. The repo's `abi/` directory
   currently contains NO handoff types (verified: no `BootHandoffV1` /
   `FirmwareHandoff` definition lives there), so this is scoped strictly as a
   recommendation: *extract a shared `abi` crate that owns `BootHandoffV1`,
   `MAX_CMDLINE_LEN`, `flags`, `pixel_format`, and all nested types; both
   `nonos-bootloader` and `nonos-kernel` depend on it; delete the duplicate
   declarations.* No fix is implemented in this task per the read-only mandate.

---

## Verdict summary

Scored cells = struct/struct-total rows + constant rows + `is_valid()` check rows
(field rows whose struct verdict is MATCH are aggregated into the struct verdict).

Scoring unit: one row per struct total, one row per constant/flag symbol, one
row per `is_valid()` check.

| verdict | count | items |
|---|---|---|
| **MATCH** | **29** | 13 struct totals (FramebufferInfo, MemoryMap, AcpiInfo, SmbiosInfo, Modules, Timing, Measurements, RngSeed, ZkAttestation, FirmwareType, FirmwareEntry, FirmwareHandoff, BootHandoffV1); 13 constants (`HANDOFF_MAGIC`, `HANDOFF_VERSION`, 11 `flags::*` bits); 3 shared `is_valid()` checks (magic, version, size) |
| **DRIFT** | **5** | `MAX_CMDLINE_LEN` no producer symbol (S2); `pixel_format::*` no producer symbol (S3); `is_valid()` missing `entry_point != 0` (S1); missing `mmap.ptr` consistency (S1); missing `mmap.entry_size` consistency (S1) |
| **UNVERIFIED** | **0** | every scored layout cell fully reduced to bytes from the `#[repr(C)]` algorithm; no struct required an `offset_of!` fallback |

Totals: **MATCH = 29, DRIFT = 5, UNVERIFIED = 0**. No cell in this document is "looks the same": every layout number is derived
from declared field types via the `#[repr(C)]` placement algorithm, and every
constant/flag is a literal read at a cited `path:line`.

Headline findings:
- **No binary layout drift.** `BootHandoffV1` is 1832 bytes, align 8, on both
  sides, with byte-identical field offsets — derived, not eyeballed. All 12
  nested types match to the byte.
- **5 contract DRIFTs, all in invariants/constants, not layout.** Highest is the
  S1 `is_valid()` asymmetry: the consumer (the defending side) enforces a strict
  subset of the producer's invariants. S2: `MAX_CMDLINE_LEN` is consumer-only and
  the producer's cmdline writer applies no cap, so >4096-byte cmdlines are
  silently truncated by the kernel.
- **Structural risk:** dual independent type declarations with no shared crate;
  parity is currently coincidental. Recommendation (not implemented): extract a
  shared `#[repr(C)]` `abi` crate and make the consumer's validator a superset of
  the producer's.

### UNVERIFIED experiments (none required for scored cells; recorded for the pointed-to follow-up surface)

No scored layout cell is UNVERIFIED. For completeness, the two out-of-`BootHandoffV1`
follow-up surfaces (pointed-to arrays, not embedded, so they do not affect the
struct table) would be settled by:

- `MemoryMapEntry` parity (producer `nonos-bootloader/src/handoff/jump/types.rs:20`
  vs consumer `src/boot/handoff/types/memory.rs:42`): a `const _: () = assert!(
  core::mem::size_of::<MemoryMapEntry>() == 40 && core::mem::offset_of!(
  MemoryMapEntry, physical_start) == 8 && core::mem::offset_of!(MemoryMapEntry,
  attribute) == 32);` compiled in *each* crate. (Hand derivation: `memory_type`
  u32@0, `_pad` u32@4, `physical_start` u64@8, `virtual_start` u64@16,
  `page_count` u64@24, `attribute` u64@32 → size 40, align 8 — fields/types
  identical both sides, so MATCH by derivation; the assert is the byte-level
  proof if a third party disputes the derivation.)
- `Modules.ptr` element type: producer declares no `Module` struct; consumer
  `Module` is `src/boot/handoff/types/info.rs:31` (`base u64@0, size u64@8,
  kind u32@16, reserved u32@20`, size 24, align 8). Settle by locating the
  producer code that fills `Modules.ptr` and asserting its element type's
  `size_of`/`offset_of!` equals the consumer `Module`'s; until that producer
  writer is identified this element ABI is UNVERIFIED (out of scope of the
  embedded-layout table; recorded as a follow-up).

---

## Build-proven pins (Task 2)

`const _: () = { ... };` blocks asserting every `BootHandoffV1` field offset and
total size == 1832 were appended to both handoff structs, and a `#[test]
fn abi_pins_match_golden()` was appended to the consumer test module. The pin
numbers are lifted verbatim from the golden table above.

Files modified:

- `src/boot/handoff/types/handoff.rs` — consumer `const _` pin block
- `nonos-bootloader/src/handoff/types/handoff.rs` — producer `const _` pin block
- `src/boot/handoff/types/tests.rs` — `#[test] fn abi_pins_match_golden()`

### Producer build result (make nonos-mk-bootloader, with pin block)

```text
   Compiling nonos_boot v1.0.5 (/…/nonos-bootloader)
warning: unused import: `core::ptr`
  --> src/handoff/exit/cleanup.rs:17:5
   |
   = note: `#[warn(unused_imports)]` on by default
warning: constant `VK_FINGERPRINT_ATTESTATION_PROGRAM` is never used
   = note: `#[warn(dead_code)]` on by default
warning: `nonos_boot` (lib) generated 2 warnings
    Finished `release` profile [optimized] target(s) in 5m 22s
```

No `error[E0080]`. All 17 const-eval asserts (16 field offsets + size_of == 1832)
passed on the producer side. **Verdict: build-proven MATCH for all 16 fields of
`BootHandoffV1`.**

### Consumer const_ block result

`cargo check --features std --target x86_64-apple-darwin` on the consumer crate
produced a single pre-existing error (`#[panic_handler] function required, but
not found` — a bare-metal crate linking issue unrelated to the handoff module),
zero errors from `src/boot/handoff/`. The consumer `const _` block is accepted
by the compiler: no `E0080` or offset-related errors emitted.

### Consumer host test result

Command attempted:

```text
cargo test --lib --features std --target x86_64-apple-darwin \
  boot::handoff::types::tests::abi_pins_match_golden -- --nocapture
```

Result: compile failed with 359 pre-existing errors in unrelated modules
(stale `crate::test::framework` imports in `src/arch/tests/`, `src/memory/tests/`,
`src/bus/tests/`, `src/process/tests/`, `src/syscall/tests/`, etc.; missing
`userland/wm/src/main.rs` include; stale `AbiEntry` struct field references).
None of these errors are in `src/boot/handoff/`. Running `cargo rustc --lib
--features std --target x86_64-apple-darwin -- --cfg test` shows only warnings
(`unused import: super::*`, `unused import: core::mem::size_of`) from the
handoff tests module — no errors. The `abi_pins_match_golden` function itself
compiles correctly; the test runner could not execute because the full crate
does not compile for host tests due to pre-existing failures in other modules.

The consumer layout is already arithmetically proven MATCH by the Task 1 golden
table derivation and confirmed by the consumer `const _` block which the compiler
accepted without error. The host `#[test]` function is instrumentation for a
future state when the pre-existing 359 compile errors in other modules are resolved.

### Note on intentional instrumentation

The producer `const _` pin block is intentional fail-loud instrumentation. If a
future build goes red on these asserts it means the ABI contract drifted — the
correct response is to update the layout on both sides to match intentionally,
not to delete the pin. A red build here is a signal, not a regression to revert.

### Open contract drifts (NOT caught by layout pins — by design)

The following drifts are invariant/constant issues, not layout. Layout pins
cannot and should not catch them. They remain open on the roadmap:

- **S1 `is_valid()` asymmetry**: producer checks `entry_point != 0`,
  `mmap.ptr != 0` when `entry_count > 0`, `mmap.entry_size != 0` when
  `entry_count > 0`; consumer checks none of these. The consumer enforces a
  strict subset of the producer's invariants — a weakened trust gate.
- **S2 `MAX_CMDLINE_LEN` producer-absent**: consumer silently truncates cmdlines
  > 4096 bytes; producer has no such cap and can emit arbitrarily long cmdlines.
