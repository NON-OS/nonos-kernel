# Multi-architecture capsules

The capsule format is multi-arch from day one. The marketplace and
the package layout do not assume x86_64. Three architectures are
declared targets:

- `x86_64-nonos`
- `aarch64-nonos`
- `riscv64-nonos`

x86_64 is the production target today. aarch64 and riscv64 are
architecturally-ready: arch-specific modules exist, the build picks
them up under the right `target_arch` cfg, and the package format
already carries multi-arch artifacts. They do not yet boot on real
hardware; that is the next runtime milestone for each.

## 1. Kernel arch surface

`src/arch/` carries one subdirectory per supported arch. Each
exports the same set of names so cross-arch kernel code does not
need cfg branches:

```
arch::cpu::{cpu_id, enable_interrupts, disable_interrupts, halt}
arch::halt_loop
arch::time::timer::init_boot_time
arch::trap (per-arch trap frame)
```

Per-arch entry points live under `arch::<arch>::boot::init`. The
boot path picks the right one via `cfg(target_arch)`.

## 2. Package side

A signed package contains one envelope and one or more
arch-specific artifacts. Each artifact carries:

```
target_triple        e.g. "x86_64-nonos"
abi_version          capsule ABI version this binary targets
kernel_abi_min       minimum kernel ABI it accepts
artifact_hash        BLAKE3(artifact_bytes)
artifact_signature   publisher signature over the artifact descriptor
artifact_bytes       the ELF
```

See `capsule_package_format.md` for the full layout.

## 3. Selection rule

The installer reads the running kernel's arch from a kernel call
(`arch_triple()`), iterates the package's artifact list, and picks
the artifact whose `target_triple` is an exact byte match. There
is no fallback. There is no emulation path inside the kernel.

A package without a matching artifact fails install with
`NoArchMatch`. The user sees a clear error; nothing is loaded.

## 4. Why no emulation fallback

If an x86_64 binary ran on an aarch64 host through an emulator the
kernel does not control, the trust boundary collapses: the
publisher signed an x86_64 artifact but the user is running it on
aarch64. Either an emulator capsule is present and authorized (and
the user is making the trust decision explicitly), or the install
fails. Silent emulation is never the answer.

## 5. ABI versioning

`abi_version` and `kernel_abi_min` are independent integers that
move together when:

- a syscall is added or its semantics change
- the manifest schema changes in a way that affects the wire
- the package format header changes

A capsule with `kernel_abi_min > kernel_abi` fails install with
`KernelTooOld`. A capsule with a too-old `abi_version` is allowed
to run if the kernel still understands its ABI; the kernel commits
to N+1 backwards compatibility for the syscall surface.

## 6. Per-arch publishing workflow

A publisher who only ships x86_64 ships a package with one
artifact. A publisher who ships all three ships three artifacts in
one package. The publisher signs the envelope once. Each artifact
is also signed individually so adding a new arch later does not
require rotating the envelope signature.

## 7. Reproducible builds

Per-arch artifacts may carry a reproducible build attestation. The
attestation is opaque to the kernel; the marketplace and the user
are the consumers. A publisher that runs deterministic builds gets
a verifiable claim that the binary in the package is the binary the
source produces. The marketplace can surface a "verified build"
badge; the kernel does not look at this.

## 8. Cross-arch endpoint compatibility

IPC endpoints are arch-agnostic. A capsule running on x86_64 can
talk to a capsule running on aarch64 inside the same NØNOS instance
(once cross-CPU-arch deployment lands). The wire format is
canonical, big-endian, and does not encode pointer width.

## 9. Status today

| Arch | Kernel boots | Capsule artifacts compile | Real hardware proof |
|---|---|---|---|
| x86_64 | yes | yes | yes (QEMU + real x86_64) |
| aarch64 | partial | not wired | no |
| riscv64 | partial | not wired | no |

`partial` means the source compiles under the right `target_arch`
gate but no smoke run has been completed end-to-end. That is the
runtime work tracked separately under the M-ARCH phases.
