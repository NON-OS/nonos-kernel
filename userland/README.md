# NONOS Userland

This tree holds every NONOS process that runs at CPL=3. The kernel runs at CPL=0; everything in `userland/` ships as ring-3 ELF binaries that the kernel loads, isolates, and talks to either through return values from a syscall or, for server capsules, through a wire protocol on top of MkIpc.

## Boundary

```
            CPL=0  (kernel)                                 CPL=3  (userland)
   ┌────────────────────────────────────┐         ┌────────────────────────────────┐
   │  syscall dispatcher                │◀────────┤  libc                          │
   │      contract::dispatch            │ SYSCALL │      crypto_random / mmap      │
   │      cap gate (Capability::resolve)│         │      _exit / read / write      │
   │                                    │         │      mk_ipc_send/recv/call     │
   │  capsule spawn                     │         │      __nonos_rt_sigreturn      │
   │      load_elf_executable           │─ ELF ──▶│  capsule_<name>                │
   │      switch_to_process_AS          │ +PT_LOAD│      _start → heap_init        │
   │      install_caps                  │         │      server: recv loop         │
   │                                    │         │      one-shot: work + _exit    │
   │  kernel-side capsule client        │         │                                │
   │      gate_caller (CAP_*)           │◀ MkIpc ─┤      mk_ipc_send to            │
   │      transport: gen-checked        │─ MkIpc ▶│        KERNEL_REPLY_ENDPOINT   │
   │      typed Err on Dead/Stale       │         │                                │
   └────────────────────────────────────┘         └────────────────────────────────┘
```

Three things cross the line and nothing else: the `SYSCALL` instruction (one site, `libc/src/syscall/raw.rs`), the ELF embedded via `include_bytes!` and loaded by the kernel-side spawn, and IPC envelopes through `MkIpcSend`/`Recv`/`Call`.

## Capsule status

| Capsule | Class | Build | Kernel mirror | Spawn site wired | Boot-test proven |
|---|---|---|---|---|---|
| capsule_proof_io | one-shot | yes | `crate::userspace::capsule_proof_io` | yes (`init::run_init`) | yes (boot run prints marker) |
| capsule_ramfs | server | yes | `src/fs/ramfs_capsule/` | yes (`init::run_init`) | yes (`tests/boot/ramfs_round_trip.sh`) |
| capsule_keyring | server | yes | `src/security/keyring_capsule/` | yes (`init::run_init`) | yes (`tests/boot/keyring_round_trip.sh`) |
| capsule_entropy | server | yes | `src/security/entropy_capsule/` | yes (`init::run_init`) | yes (`tests/boot/entropy_round_trip.sh`) |
| capsule_crypto | server | yes | `src/security/crypto_capsule/` | yes (`init::run_init`) | yes (`tests/boot/crypto_hash_round_trip.sh`) |
| capsule_vfs | server | yes | `src/fs/vfs_capsule/` | yes (`init::run_init`) | yes (`tests/boot/vfs_round_trip.sh`) |
| capsule_market | server | yes | `src/security/market_capsule/` | yes (`init::run_init`, cfg-gated) | yes (`tests/boot/market_round_trip.sh`) |
| capsule_driver_virtio_rng | server | yes | `src/hardware/virtio_rng_capsule/` | yes (`init::run_init`, cfg-gated) | yes (`tests/boot/virtio_rng_round_trip.sh`) |
| capsule_driver_virtio_blk | server | yes | `src/hardware/virtio_blk_capsule/` | yes (`init::run_init`, cfg-gated) | yes (`tests/boot/virtio_blk_round_trip.sh`) |
| capsule_wallpaper | one-shot | yes | none | none | none |

`marketplace_abi/` is a library crate, not a capsule; it ships the wire-form types `capsule_market` and the host `marketplace-index` CLI both speak.

`capsule_wallpaper` is parked. The userland binary builds, but no kernel mirror, no spawn call, no client. It returns when the framebuffer broker primitive (`MkFramebufferMap`) lands; until then the `nonos-capsule-wallpaper` Cargo feature has no effect.

## Layout

```
userland/
├── x86_64-nonos-user.json         target spec for every binary in this tree
├── libc/                          the only userland runtime; every capsule depends on it
│   ├── Cargo.toml
│   └── src/
│       ├── broker/                MkDevice* / MkMmio* / MkIrq* / MkDma*
│       ├── crypto/                crypto_random, crypto_encrypt, crypto_decrypt
│       ├── graphics/              nonos_display_dimensions, nonos_surface_*
│       ├── heap/                  heap_init + global allocator (mmap-backed)
│       ├── ipc/                   mk_ipc_send, mk_ipc_recv, mk_ipc_call
│       ├── mem/                   mmap
│       ├── signal/                rt_sigreturn trampoline
│       ├── syscall/               call_raw + numeric constants (kernel is source of truth)
│       ├── unistd/                _exit, read, write, mk_yield
│       ├── lib.rs                 the public surface
│       └── panic.rs               _exit(134), the SIGABRT exit-code convention
├── marketplace_abi/               library; wire-form types for the marketplace index
├── capsule_proof_io/              one-shot, prints a marker, exits
├── capsule_ramfs/                 server, owns /ram namespace
├── capsule_keyring/               server, owns the per-PID key store
├── capsule_entropy/               server, owns the userland random authority
├── capsule_crypto/                server, owns hashing today (BLAKE3, SHA3-256)
├── capsule_vfs/                   server, owns the fd table and path resolution
├── capsule_market/                server, owns the signed marketplace index
├── capsule_driver_virtio_rng/     server, drives virtio-rng through the broker
├── capsule_driver_virtio_blk/     server, drives virtio-blk through the broker
└── capsule_wallpaper/             one-shot, parked behind MkFramebufferMap
```

Three crate kinds. `libc` is a static library (`staticlib + rlib`). `marketplace_abi` is an rlib. The `capsule_*` directories are `bin` crates. Nothing else lives here.

## Toolchain

| Pin | Source of truth |
|---|---|
| `nightly-2026-01-16` | `Makefile` `TOOLCHAIN :=` |
| `x86_64-nonos-user` target | `userland/x86_64-nonos-user.json` |
| `-Zbuild-std=core,alloc` | every Makefile capsule rule |

Every capsule and the libc are built with this exact toolchain. Mixing toolchains within `userland/` is a bug; build artifacts will pick up incompatible `compiler_builtins` revisions.

## Target spec

`userland/x86_64-nonos-user.json` is the userland target. It pins:

- `target-pointer-width: 64`, `arch: x86_64`, `vendor: unknown`, `os: nonos`
- `panic-strategy: abort`
- no red zone (kernel manages signal stacks, no leaf-function stack reuse)
- statically linked, no dynamic linker
- single `_start` entry, no `_main`/CRT shim

The kernel's own target is `x86_64-nonos.json`. The userland target is distinct so that no userland binary ever sees a kernel-only relocation type or feature.

## The libc

`userland/libc/` is the single runtime that every capsule links against. It is `no_std`, exposes a `_start`/`_exit` ABI, owns the panic handler, owns the heap allocator, and owns every syscall wrapper. Capsule code does not call `syscall` instructions directly; it calls a libc wrapper.

### Surface

| Family | Module | Symbols |
|---|---|---|
| Process control | `unistd` | `_exit`, `read`, `write` |
| Memory | `mem` | `mmap` |
| Heap | `heap` | `init` (alias `heap_init`), `HeapError` |
| IPC | `ipc` | `mk_ipc_send`, `mk_ipc_recv`, `mk_ipc_call` |
| Crypto | `crypto` | `crypto_random`, `crypto_encrypt`, `crypto_decrypt` |
| Graphics | `graphics` | `nonos_display_dimensions`, `nonos_surface_create/destroy/map/present_full`, `NONOS_PIXEL_FMT_ARGB8888` |
| Signal trampoline | `signal` | `__nonos_rt_sigreturn` |
| Panic | `panic` | `_exit(134)` (private) |

### Allocator

`heap::init()` binds 4 MiB of anonymous private mmap as the allocator backing, then hands ownership to a `linked_list_allocator`. Allocations beyond 4 MiB are not currently grown; OOM goes through `alloc_error_handler`, which calls the panic handler, which calls `_exit(134)`. A capsule that cannot allocate cannot serve, so abort is the correct response.

`heap_init()` is one-shot. The first successful call locks initialisation; later calls return `HeapError::AlreadyInitialized`. Server capsules must call it before their `run()` loop. One-shot capsules that never allocate do not need to call it.

### Panic

`#[panic_handler]` calls `_exit(134)`. 134 is `128 + 6`, the conventional SIGABRT exit code. The kernel observes it through normal process exit accounting. There is no userland panic message printed, and no double-fault path; the panic handler returns `!`.

### Syscall trampoline

```
rax = number
rdi = a1, rsi = a2, rdx = a3
r10 = a4 (rcx is clobbered by SYSCALL itself)
r8  = a5
r9  = a6
return in rax
clobbers: rcx (return RIP), r11 (return RFLAGS)
```

`raw()` in `libc/src/syscall/raw.rs` is the only place this assembly lives. Every wrapper goes through `call_raw(N_*, [u64; 6])`. There is no second syscall path.

### Syscall numbering blocks

Kernel side is the source of truth (`crate::syscall::numbers::SyscallNumber`). The libc mirrors numbers in `userland/libc/src/syscall/numbers.rs`.

| Range | Family |
|---|---|
| 0..99 | POSIX-shape (read=0, write=1, mmap=9, rt_sigreturn=15, exit=60) |
| 900..999 | crypto (random=900, encrypt=904, decrypt=905) |
| 1300..1399 | graphics (display dims=1300, surface create=1301, destroy=1302, map=1303, present_full=1304) |
| 0x1000..0x1FFF | microkernel IPC (send=0x1000, recv=0x1001, call=0x1002) |

When adding a new family, claim a block. Do not interleave new numbers into an existing block.

## Capsule classes

Two patterns coexist. Each has a different kernel-side lifecycle contract.

### Server capsule

`heap_init` first, then an infinite `run()` that drives `mk_ipc_recv` and writes back via `mk_ipc_send`. The kernel side allocates a SERVICE_PORT and a REPLY_PORT, registers the capsule in the service registry, tracks liveness against the process table, and bumps a generation counter on respawn so stale handles fail deterministically.

Examples: `capsule_ramfs`, `capsule_keyring`, `capsule_entropy`, `capsule_crypto`, `capsule_vfs`, `capsule_market`, `capsule_driver_virtio_rng`, `capsule_driver_virtio_blk`.

### One-shot capsule

Do work, then `_exit(N)`. No IPC server, no liveness tracking, no generation counter, no restart expectation. The kernel spawns it, waits for the exit code (or just observes it left), and moves on.

Examples: `capsule_proof_io`, `capsule_wallpaper`.

A capsule must be one or the other. Do not write a half-server, half-one-shot. If you need a one-shot that occasionally accepts an IPC, it is a server with a short timeout.

## Process lifecycle

Every spawn function in `src/{security,fs}/<name>_capsule/spawn.rs` runs the same pipeline. Every step is observable in source under the named module path; there is no implicit step.

```
   spawn_<name>_capsule()
            │
            ▼
   nonos_inbox::register_inbox(REPLY_INBOX)     server only
   register_endpoint(REPLY_INBOX, …, pid=0)     kernel-owned reply inbox
            │
            ▼
   create_process(name, Ready, Normal)          → process::address_space::lifecycle::allocate
            │                                     creates the per-PCB address space
            ▼
   switch_to_process_address_space(pid)         CR3 := capsule
            │
            ▼
   load_elf_executable(BIN)                     PT_LOAD segments map into the capsule AS
            │
            ▼
   switch_address_space(KERNEL_ASID)            CR3 := kernel
            │                                   ├─ Ok    →  continue
            │                                   └─ Err   →  serial println [FATAL] + halt_loop
            ▼
   install_caps(pid, IPC | Memory | Crypto)     explicit; no implicit cap escalation
            │
            ▼
   allocate_service_stack(pid)
   setup_initial_context(pid, entry, stack_top)
            │
            ▼
   register_endpoint(SERVICE_NAME, port, pid, caps)   server only
            │
            ▼
   add_to_run_queue(pid)
   state.set_alive(pid)                         bumps generation; the new epoch is live

   ── from here the scheduler dispatches _start ──

       server capsule:               one-shot capsule:
       heap_init()                   linear work via syscalls
       loop {                         _exit(N)
         mk_ipc_recv → dispatch
         mk_ipc_send to REPLY
       }
```

`switch_address_space(KERNEL_ASID)` failure is fail-hard. Continuing in an unknown CR3 would corrupt every later capsule operation, so the kernel halts instead of returning.

### What the kernel installs at spawn

| Resource | Source |
|---|---|
| Address space | `crate::process::address_space::lifecycle::allocate` (called by `create_process`) |
| CR3 switch for ELF load | `crate::memory::paging::manager::switch_to_process_address_space(pid)` |
| ELF image | `crate::elf::loader::load_elf_executable(BIN)` |
| CR3 rollback | `crate::memory::paging::manager::switch_address_space(KERNEL_ASID)` (fail-hard on error) |
| Capability mask | `Capability::IPC.bit() \| Capability::Memory.bit() \| Capability::Crypto.bit()` (default) |
| Stack | `crate::kernel_core::process_spawn::allocate_service_stack(pid)` |
| Initial context | `crate::kernel_core::process_spawn::setup_initial_context(pid, entry, stack_top)` |
| Service endpoint | `crate::services::registry::register_endpoint(SERVICE_NAME, SERVICE_PORT, pid, caps)` (server only) |
| Reply inbox | `crate::ipc::nonos_inbox::register_inbox(REPLY_INBOX)` (server only) |
| Lifecycle state | `crate::services::lifecycle::CapsuleState` (shared primitive: pid, generation, is_alive) |

A capsule may need additional caps; if it does, the spawn function for that capsule grants them explicitly. There is no implicit cap escalation; any cap the capsule does not get at spawn it can never get.

## IPC contract for server capsules

Two wire-header shapes coexist during the migration. New capsules use the v1 header; ramfs and keyring still use the seq-only header until they are rewritten on top of v1.

### v1 header (20 bytes)

```
request:   [u32 magic][u16 version][u16 op][u16 flags][u16 reserved]
           [u32 request_id][u32 payload_len][payload...]
response:  [u32 magic][u16 version][u16 op][u16 flags][u16 reserved]
           [u32 request_id][u32 payload_len][i32 status][body...]
```

All fields little-endian, packed, no alignment padding. `magic` and `version` are the protocol fingerprint per capsule (NOEN/NOCX/NOVF/NMKT/NORD/NBLK for entropy/crypto/vfs/market/virtio_rng/virtio_blk); a wrong magic or wrong version is rejected with `EINVAL` before any handler runs. `request_id` is allocated by the kernel-side client (atomic counter); the capsule echoes it on the response so the client can match replies even when interleaved. `status` rides in the first 4 bytes of the response payload; 0 on success, negative errno on failure.

Used by: `capsule_entropy`, `capsule_crypto`, `capsule_vfs`, `capsule_market`, `capsule_driver_virtio_rng`, `capsule_driver_virtio_blk`.

### Legacy seq header (8 bytes)

```
request:   [u32 seq][u16 op][u16 reserved][payload...]
response:  [u32 seq][i32 status][body...]
```

Used by: `capsule_ramfs`, `capsule_keyring`. Migration to the v1 header is a follow-up slice; the runtime contract (no panic on untrusted input, bounded payload, deterministic errno mapping) is identical.

### Per-op payload

The header is followed by the op-specific payload. Layouts are documented per capsule alongside the wire encoders. Example for keyring `STORE`:

```
request:  [u32 caller_pid][u64 now][u64 expires_at][u8 key_type][u16 data_len][data...]
response: [u32 key_id]
```

`caller_pid`, `now`, and `expires_at` are filled in by the kernel-side client from `current_pid()` and `crate::time::timestamp_millis()`. The capsule does not read them from the underlying recv buffer except via this payload, and it never trusts them from any other source.

### Trusted identity

`caller_pid` enters the wire payload only because the kernel-mediated client put it there. There is no path by which a capsule can read identity from anywhere else: the recv buffer is the only source of input, and the kernel client is the only writer to that buffer for the relevant request type. This is the entire reason the capsule can act on per-PID ownership decisions safely.

### Round-trip

```
   kernel caller          gate_caller            transport               capsule (CPL=3)
        │                      │                     │                        │
        │  client::op(args)    │                     │                        │
        ├─────────────────────▶│                     │                        │
        │                      │ pid = current_pid() │                        │
        │                      │ has_capability(...) │                        │
        │   AccessDenied       │                     │                        │
        │◀─────────────────────┤   (cap miss)        │                        │
        │                      │                     │                        │
        │                      │  caller_pid         │                        │
        │                      ├────────────────────▶│                        │
        │                      │                     │ seq = next_request_id()│
        │                      │                     │ gen = state.generation()
        │                      │                     │ encode + enqueue       │
        │                      │                     ├───────────────────────▶│ recv
        │                      │                     │                        │ decode + dispatch
        │                      │                     │                        │ enforce owner==pid
        │                      │                     │                        │ encode reply
        │                      │                     │  reply on REPLY_INBOX  │
        │                      │                     │◀───────────────────────┤ send
        │                      │                     │                        │
        │                      │                     │ if !is_alive       → Dead
        │                      │                     │ if gen changed     → Stale
        │                      │                     │ match seq, decode status
        │   Ok(payload) / Err  │                     │                        │
        │◀─────────────────────┴─────────────────────┤                        │
```

The generation gate runs on every iteration of the recv spin and on the dequeue path before the body is decoded. A respawn between enqueue and reply surfaces as `Stale` even if the new epoch happens to allocate the same `request_id`.

### Failure modes

| Failure | Detection | Result |
|---|---|---|
| Capsule not running | `state::is_alive()` returns false at send time | `Err(Dead)` |
| Capsule died mid-call | `state::is_alive()` rechecks each yield | `Err(Dead)` |
| Reply lost / no response within RECV_YIELDS | counter exhaustion | `Err(TransportFailure)` |
| Reply payload malformed | `decode_response` returns None | `Err(ProtocolMismatch)` |
| Reply payload wrong length for op | per-op check after status | `Err(ProtocolMismatch)` |
| Status != 0 | per-op `errno::map(status)` | typed `Err(NotFound | AccessDenied | ...)` |

There is no infinite wait. The transport spins through `crate::sched::yield_now()` for at most `RECV_YIELDS` iterations, then gives up.

### Endpoint and port allocation

Every server capsule needs two ports and one reply inbox name. Current allocation:

| Capsule | SERVICE_PORT | REPLY_PORT | KERNEL_REPLY_ENDPOINT | REPLY_INBOX | Header |
|---|---|---|---|---|---|
| ramfs | 4096 | 4097 | 0x1_0000_0001 | endpoint.4294967297 | seq |
| keyring | 4098 | 4099 | 0x1_0000_0002 | endpoint.4294967298 | seq |
| entropy | 4100 | 4101 | 0x1_0000_0003 | endpoint.4294967299 | v1 |
| crypto | 4102 | 4103 | 0x1_0000_0004 | endpoint.4294967300 | v1 |
| vfs | 4104 | 4105 | 0x1_0000_0005 | endpoint.4294967301 | v1 |
| market | 4106 | 4107 | 0x1_0000_0007 | endpoint.4294967303 | v1 |
| driver.virtio_rng | 4200 | 4201 | 0x1_0000_0006 | endpoint.4294967302 | v1 |
| driver.virtio_blk0 | 4202 | 4203 | 0x1_0000_0008 | endpoint.4294967304 | v1 |

Rule: services capsules use the 4096-block; driver capsules use the 4200-block. Claim the next free even SERVICE_PORT, the odd port immediately after as REPLY_PORT, and the next reply endpoint above the 32-bit boundary. The numeric REPLY_INBOX is the decimal of KERNEL_REPLY_ENDPOINT; both kernel-side `spawn_*_capsule()` and userland `KERNEL_REPLY_ENDPOINT` constants must agree.

`docs/production-ledger/05-loader-exec-userspace/capsule-conventions.md` is the canonical allocation table.

## Restart semantics

A server capsule's in-process state is owned by the capsule, not by the kernel. `services::lifecycle::CapsuleState` keeps a generation counter that bumps on every successful spawn, and the per-capsule transport captures the generation at send time. If the generation shifts before the reply lands — i.e. the capsule was respawned mid-call — the transport returns `Stale`, which surfaces as `ESTALE` (or the API's deterministic stale-handle error, e.g. `EIO` for capsule fds). There is no same-request-id collision risk across epochs because the generation gate runs first.

Respawn means an empty store. There is no persistence on the userland side. Capsule respawn is the boundary at which all in-flight ephemeral state is cleared, by design.

## Capability model

Two distinct capability namespaces coexist in the same per-PID `caps: u64` word and are checked by `crate::services::caps::has_capability(pid, bit)` against `crate::syscall::microkernel::capability::CAP_TABLE`.

| Source | Examples | Purpose |
|---|---|---|
| `crate::capabilities::Capability` | `IPC` (8), `Memory` (16), `Crypto` (32) | what a capsule itself needs to run |
| `crate::services::caps::CAP_*` | `CAP_VFS` (1<<0), `CAP_CRYPTO` (1<<4), `CAP_ENTROPY` (1<<15), `CAP_KEYRING` (1<<16) | what a caller needs to invoke a service |

The bit positions do not overlap; `Capability::Memory` is bit 4 (value 16), `CAP_KEYRING` is bit 16 (value 65536). They share the same word safely.

A capsule itself does not need its own service capability. `capsule_keyring` does not hold `CAP_KEYRING`; it is the keyring. `capsule_entropy` does not hold `CAP_ENTROPY`. Callers do. The kernel-side client checks this at the top of every entry function via `capability::gate_caller()` (or per-op `gate_*` for capsules with multiple cap classes), which reads `current_pid()` and verifies the cap. There is no other entry point into a server capsule on the live path.

## Boot sequence

The capsule spawn points are inside `crate::userspace::init::run_init`. The order is fixed: ramfs first (so anything reading configuration off `/ram` has it), then keyring, then the newer service capsules.

```
init_core_systems
    boot_log + serial
    memory init
    process table init
    capabilities init for init PCB
    ipc init
    crypto rng + kernel keys
    network stack init

userspace::run_init
    spawn legacy *_engine kthreads          gated on nonos-legacy-tree
        crypto engines, signature engines, pq engines, zk engines,
        system services (netmgr, tls, wallet, storage, udev)
    spawn_ramfs_capsule                     real CPL=3 capsule
    spawn_keyring_capsule                   real CPL=3 capsule
    spawn_entropy_capsule                   real CPL=3 capsule
    spawn_crypto_capsule                    real CPL=3 capsule
    spawn_vfs_capsule                       real CPL=3 capsule
    spawn_market_capsule                    cfg-gated on nonos-capsule-market
    spawn_driver_virtio_rng_capsule         cfg-gated on nonos-capsule-driver-virtio-rng
    spawn_driver_virtio_blk_capsule         cfg-gated on nonos-capsule-driver-virtio-blk
    spawn legacy core services              gated on nonos-legacy-tree
    lower init priority
    capsule_proof_io::launch                one-shot, replaces init image
    init_loop
```

`spawn_*_capsule` failures are logged and discarded. The kernel does not fall back to an in-kernel replacement; later requests against the dead capsule return `Err(Dead)` deterministically.

## Cargo profile

Every `capsule_*` crate uses the same release profile:

| Setting | Value | Reason |
|---|---|---|
| `panic` | `abort` | no unwind tables in userland; `_exit(134)` is the panic path |
| `opt-level` | `2` | favour code size and predictable codegen over `3`'s aggressive vectorisation |
| `lto` | `false` | LTO across `compiler_builtins` + `linked_list_allocator` is brittle on `-Zbuild-std`; off until proven necessary |
| `debug` | `false` | release artifacts ship stripped |
| `strip` | `true` | symbol table not needed; the kernel embeds the binary as bytes |

Dev profile mirrors release except `opt-level = 0` and `debug = true`.

## Feature gates

The kernel toggles capsule embed sites via Cargo features in the kernel `Cargo.toml`:

| Feature | Embeds | Spawns |
|---|---|---|
| `nonos-capsule-proof-io` | `capsule_proof_io` | one-shot via `capsule_proof_io::launch()` |
| `nonos-capsule-ramfs` | `capsule_ramfs` | server via `spawn_ramfs_capsule` |
| `nonos-capsule-keyring` | `capsule_keyring` | server via `spawn_keyring_capsule` |
| `nonos-capsule-entropy` | `capsule_entropy` | server via `spawn_entropy_capsule` |
| `nonos-capsule-crypto` | `capsule_crypto` | server via `spawn_crypto_capsule` |
| `nonos-capsule-vfs` | `capsule_vfs` | server via `spawn_vfs_capsule` |
| `nonos-capsule-market` | `capsule_market` | server via `spawn_market_capsule` |
| `nonos-capsule-driver-virtio-rng` | `capsule_driver_virtio_rng` | server via `spawn_driver_virtio_rng_capsule` |
| `nonos-capsule-driver-virtio-blk` | `capsule_driver_virtio_blk` | server via `spawn_driver_virtio_blk_capsule` |
| `nonos-ramfs-smoketest` | adds `crate::fs::ramfs_capsule::smoketest::run()` after spawn | n/a |
| `nonos-keyring-smoketest` / `nonos-entropy-smoketest` / `nonos-crypto-hash-smoketest` / `nonos-vfs-smoketest` / `nonos-market-smoketest` / `nonos-driver-virtio-rng-smoketest` / `nonos-driver-virtio-blk-smoketest` | runs the matching `smoketest::run()` after spawn | n/a |

When a feature is off, the kernel-side `embed.rs` resolves the binary slice to `&[]`, and `spawn_*_capsule()` returns `Err(FeatureDisabled)` immediately. The kernel still builds.

## Build

The Makefile owns every userland build target. Do not invoke `cargo` against a capsule directly outside of the Makefile; the toolchain pin, target spec, and `-Zbuild-std` flags are coordinated there.

```
make nonos-mk-libc                  builds the static libc archive
make nonos-mk-marketplace-abi       builds the marketplace_abi rlib
make nonos-mk-proof-io              builds capsule_proof_io
make nonos-mk-ramfs                 builds capsule_ramfs
make nonos-mk-keyring               builds capsule_keyring
make nonos-mk-entropy               builds capsule_entropy
make nonos-mk-crypto                builds capsule_crypto
make nonos-mk-vfs                   builds capsule_vfs
make nonos-mk-market                builds capsule_market (production)
make nonos-mk-market-dev            same, with the offline dev fixture
make nonos-mk-market-smoke          same, with the smoketest-trust feature
make nonos-mk-virtio-rng            builds capsule_driver_virtio_rng
make nonos-mk-virtio-blk            builds capsule_driver_virtio_blk
make nonos-mk-marketplace-index-tool  builds the host marketplace-index CLI
```

`capsule_wallpaper` does not yet have a Makefile target; it is built directly from its directory while the graphics lane settles on a target name.

The kernel embeds capsule binaries via `include_bytes!`. The kernel build will fail if a capsule feature is on but the capsule binary is not present at the expected path. Build the capsule first, then the kernel:

```
make nonos-mk-ramfs nonos-mk-capsules
make nonos-mk-keyring nonos-mk-capsules
```

`nonos-mk-capsules` turns on the runtime baseline (`microkernel-capsules` = proof_io + ramfs + keyring). Newer capsules (entropy, crypto, vfs, market, virtio_rng, virtio_blk) ride their own smoketest profiles: `nonos-mk-entropy-test`, `nonos-mk-crypto-hash-test`, `nonos-mk-vfs-test`, `nonos-mk-market-test`, `nonos-mk-driver-virtio-rng-test`, `nonos-mk-driver-virtio-blk-test`. Each profile builds the kernel with the matching capsule embed plus its boot smoke arm.

## Adding a new capsule

1. Pick the class. Server or one-shot. If you cannot answer in one sentence, do not ship it.
2. Create `userland/capsule_<name>/` with the same `Cargo.toml` shape as an existing capsule of the same class. Use `package = "nonos_userland_libc"` for the libc dep.
3. Write `src/main.rs` with `#![no_std] #![no_main]`, `#[no_mangle] pub unsafe extern "C" fn _start() -> !`, and either a `heap_init` + `run()` loop (server) or linear work + `_exit(N)` (one-shot).
4. If server: pick the next free SERVICE_PORT/REPLY_PORT pair and the next KERNEL_REPLY_ENDPOINT from the allocation table above. Update both the userland constant and the kernel-side spawner. Update `capsule-conventions.md`.
5. Add a Makefile target after the existing capsule targets. Pattern matches `ramfs_capsule`. Update `.PHONY`.
6. Add a Cargo feature `nonos-capsule-<name>` in the kernel's `Cargo.toml`.
7. Add a kernel-side mirror under the appropriate domain (`src/<domain>/<name>_capsule/`) with `embed.rs`, `error.rs`, `state.rs` (server only), `spawn.rs`, `protocol/` and `client/` (server only).
8. Wire `spawn_<name>_capsule()` into `src/userspace/init/entry.rs`.
9. Add a `kernel-with-<name>` Makefile rule that turns on the new feature alongside its dependencies.

## File-size discipline

Every file in this tree targets ~75 lines and one responsibility. `mod.rs` is declarations and re-exports only; logic lives in sibling files and is named by purpose (`store/state.rs`, not `store/util.rs`). When a file grows past one concept, split it before adding more.

## What this tree is not

It is not a place for shared utility crates. The libc is the only crate every capsule depends on. If two capsules want to share code, the right answer is to grow the libc surface, not to introduce a sibling utility crate.

It is not a place for long-running daemons that own kernel state. State that must survive a respawn lives kernel-side. Capsules are stateless across restarts by design; the kernel-side mirror is what tracks liveness and generation.

It is not a place for build configuration. The Makefile owns build orchestration. Per-capsule `.cargo/config.toml` files do not belong here.

It is not a place for syscall numbering decisions. Numbers come from `crate::syscall::numbers::SyscallNumber` on the kernel side. The libc constants in `libc/src/syscall/numbers.rs` are a mirror, not a source.

It is not a place for capability bit assignments. Cap bits come from `crate::capabilities::types::Capability` and `crate::services::caps::CAP_*` on the kernel side. The userland never assigns its own.

## Glossary

| Term | Meaning |
|---|---|
| Capsule | a single userland binary that owns one well-defined responsibility |
| Server capsule | infinite recv loop, owns persistent in-process state across requests, one PID for the lifetime of the boot |
| One-shot capsule | linear work then exit, no IPC server, no restart expectation |
| KERNEL_REPLY_ENDPOINT | numeric ID of the inbox the capsule sends responses to; lives above the 32-bit boundary by convention |
| REPLY_INBOX | string form of the above (`endpoint.<decimal>`), used by `nonos_inbox` lookups |
| Generation | monotonic counter in `state.rs` that bumps each time the capsule respawns; kernel handles compare against it to detect stale-after-respawn |
| Kernel-side mirror | the `src/<domain>/<name>_capsule/` tree that owns the spawn point, the IPC client, and the typed error surface for one userland capsule |
| `caller_pid` | the PID of the kernel-side caller, embedded into the request payload by the trusted client; the capsule never reads identity from any other source |
