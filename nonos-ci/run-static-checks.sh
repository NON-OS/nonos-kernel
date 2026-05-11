#!/usr/bin/env bash
# Static gates that microkernel-baseline.yml::static-checks runs.
# Same script for local and CI; a green run here means the gate passes.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

cargo_toml="Cargo.toml"
baselines_dir="nonos-ci/baselines"
helper="nonos-ci/check-baseline.sh"
profiles_check="nonos-ci/check-feature-profiles.py"

fail=0
note() { printf '[%s] %s\n' "$1" "$2"; }
fail_with() { printf '::error::%s\n' "$1" >&2; fail=1; }

# Cargo.toml shape
if grep -Fxq 'default = ["microkernel-core"]' "${cargo_toml}"; then
    note ok "default = [\"microkernel-core\"]"
else
    fail_with "default profile must be the exact line: default = [\"microkernel-core\"]"
fi

if grep -nE '^[[:space:]]*nonos[[:space:]]*=[[:space:]]*\[' "${cargo_toml}" >/dev/null; then
    fail_with "active 'nonos = [...]' profile detected; the legacy profile must stay in docs/legacy/Cargo.monolithic.toml"
    grep -nE '^[[:space:]]*nonos[[:space:]]*=[[:space:]]*\[' "${cargo_toml}" >&2 || true
else
    note ok "no active 'nonos = [...]' profile"
fi

# Forbidden gates not in any production microkernel profile
if [ ! -x "${profiles_check}" ]; then
    fail_with "missing or non-executable: ${profiles_check}"
elif ! python3 "${profiles_check}" "${cargo_toml}"; then
    fail_with "feature-profile check failed"
fi

run_baseline() {
    if ! bash "${helper}" "$1" "$2" "$3"; then
        fail=1
    fi
}

cfg_count="$( { grep -rn 'cfg(target_arch' src --include='*.rs' || true; } | { grep -v '^src/arch/' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'cfg(target_arch) outside src/arch' "${baselines_dir}/cfg-target-arch-count.txt" "${cfg_count}"

mem_count="$( { grep -rn 'crate::mem::' src --include='*.rs' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'crate::mem::* use sites' "${baselines_dir}/crate-mem-uses.txt" "${mem_count}"

sched_count="$( { grep -rn 'crate::sched::' src --include='*.rs' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'crate::sched::* use sites' "${baselines_dir}/crate-sched-uses.txt" "${sched_count}"

# Direct `crate::arch::x86_64::*` imports outside `src/arch/`. Generic
# kernel code should reach the platform through the `Arch` trait
# (`src/arch/abi.rs`); a direct path import is an arch-leak. Shrink
# only.
arch_leak_count="$( { grep -rn 'crate::arch::x86_64::' src --include='*.rs' || true; } | { grep -v '^src/arch/' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'crate::arch::x86_64::* outside src/arch' "${baselines_dir}/arch-x86_64-uses.txt" "${arch_leak_count}"

# `CURRENT_PID` is a global atomic written by the scheduler and the
# initial bootstrap path. Once SMP goes live this state has to move
# to per-CPU storage (see docs/hardware/cpu_smp_model.md finding #2).
# Every additional writer outside the scheduler/core owner is a new
# SMP hazard, so the baseline is shrink-only.
current_pid_writers="$( { grep -rn 'CURRENT_PID\.store' src --include='*.rs' || true; } | { grep -vE '^src/(process/(scheduler/|core/(api|init|suspend|table)))' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'CURRENT_PID writers outside scheduler/core' "${baselines_dir}/current-pid-writers.txt" "${current_pid_writers}"

# Deprecated VMM shim. Canonical owner is `memory::paging::manager`.
# Migration baseline: count must only shrink. Bump down each time a
# caller is moved off `memory::virt::*`.
virt_count="$( { grep -rn 'memory::virt' src --include='*.rs' || true; } | { grep -v '^src/memory/virt/' || true; } | { grep -v '^src/memory/mod.rs' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'memory::virt deprecated-shim use sites' "${baselines_dir}/memory-virt-uses.txt" "${virt_count}"

# Deleted Linux-shape syscall surfaces. Any reintroduction fails the
# gate.
for path in \
    'src/syscall/extended' \
    'src/syscall/aio' \
    'src/syscall/splice' \
    'src/syscall/bpf' \
    'src/syscall/ptrace' \
    'src/syscall/robust_futex' \
    'src/syscall/rseq' \
    'src/syscall/seccomp' \
    'src/syscall/mqueue' \
    'src/syscall/namespace' \
    'src/syscall/pkey' \
    'src/syscall/process_vm' \
    'src/syscall/xattr' \
    'src/syscall/fanotify' \
    'src/syscall/vdso' \
    'src/syscall/cgroup' \
    'src/syscall/capsule' \
    'src/syscall/dispatch/file_io.rs' \
    'src/syscall/dispatch/process.rs' \
    'src/syscall/dispatch/hardware' \
    'src/syscall/dispatch/network' \
    'src/syscall/dispatch/router/admin.rs' \
    'src/syscall/dispatch/router/file_fs.rs' \
    'src/syscall/dispatch/router/memory.rs' \
    'src/syscall/dispatch/router/network.rs' \
    'src/syscall/dispatch/router/process.rs' \
    'src/syscall/dispatch/router/signal.rs' \
    'src/syscall/dispatch/router/time.rs'; do
    if [ -e "${path}" ]; then
        fail_with "deleted Linux-shape path reintroduced: ${path}"
    fi
done
note ok "deleted Linux-shape syscall paths still gone"

# User-facing CryptoHash/CryptoRandom now route through the userland
# crypto/entropy capsules. The old kernel-resident shims must not come
# back: `crate::crypto::syscall_blake3_hash`, `crate::crypto::sha256_hash`,
# and `crate::crypto::sha512_hash` were the syscall-layer wrappers that
# served caller hashes from kernel-resident primitives. The kernel
# primitives themselves stay (loader, secure-boot, KDF); only the
# user-facing wrappers are gone.
forbidden_user_hash_callers="$( { grep -rn 'crate::crypto::syscall_blake3_hash\|crate::crypto::sha256_hash\|crate::crypto::sha512_hash' src --include='*.rs' || true; } | { grep -v '^src/test/' || true; } | { grep -v '^src/crypto/tests/' || true; } || true)"
if [ -n "${forbidden_user_hash_callers}" ]; then
    fail_with "user-facing kernel hash shims must not be called; route through crypto_capsule client"
    printf '%s\n' "${forbidden_user_hash_callers}" >&2
else
    note ok "no active-build callers of crate::crypto::{syscall_blake3_hash,sha256_hash,sha512_hash}"
fi

# `handle_crypto_random` must not call the kernel RNG directly for user
# requests. Boot-time/TCB callers may still use `crate::crypto::fill_random`
# (they are out of scope here); the syscall path goes through the
# entropy capsule.
random_kernel_path="$(grep -n 'crate::crypto::fill_random' src/syscall/dispatch/crypto/random.rs 2>/dev/null || true)"
if [ -n "${random_kernel_path}" ]; then
    fail_with "handle_crypto_random must route through entropy_capsule client, not kernel fill_random"
    printf '%s\n' "${random_kernel_path}" >&2
else
    note ok "handle_crypto_random does not call kernel fill_random"
fi

# `handle_crypto_encrypt`/`handle_crypto_decrypt` must not call kernel
# AEAD primitives directly for user requests. Kernel-internal callers
# (kernel_selftest, KAT, ramfs/cryptofs sealed state) keep using the
# longer module paths (`crate::crypto::chacha20poly1305::aead_encrypt`,
# `crate::crypto::aes_gcm::aes256_gcm_encrypt`); user-facing service
# calls go through the crypto capsule.
aead_kernel_path="$(grep -n 'crate::crypto::chacha20poly1305_encrypt\|crate::crypto::chacha20poly1305_decrypt\|crate::crypto::aes256_gcm_encrypt\|crate::crypto::aes256_gcm_decrypt\|crate::crypto::aes128_gcm_encrypt\|crate::crypto::aes128_gcm_decrypt' src/syscall/dispatch/crypto/aead.rs 2>/dev/null || true)"
if [ -n "${aead_kernel_path}" ]; then
    fail_with "handle_crypto_encrypt/decrypt must route through crypto_capsule client, not kernel AEAD shims"
    printf '%s\n' "${aead_kernel_path}" >&2
else
    note ok "handle_crypto_encrypt/decrypt do not call kernel AEAD shims"
fi

# Kernel-resident `*_engine` modules were the legacy in-kernel service
# threads. The microkernel runs userland capsules over `MkIpc*`, not
# kernel threads in PCB clothing. Any reintroduction of a `*_engine`
# directory under `src/services/` fails the gate.
rogue_engines="$(find src/services -maxdepth 1 -type d -name '*_engine' 2>/dev/null | wc -l | tr -d '[:space:]')"
if [ "${rogue_engines}" -ne 0 ]; then
    fail_with "src/services/*_engine reappeared; kernel-resident engines were deleted in favour of userland capsules"
    find src/services -maxdepth 1 -type d -name '*_engine' >&2
else
    note ok "no src/services/*_engine kernel-resident services"
fi

# Truth gate: real userland lives under `userland/capsule_*/`. Anything
# placed under `src/userspace/*_service/` or `src/userspace/` at all in
# this layout is a kernel-resident wrapper pretending to be userspace.
fake_userspace="$( { find src/userspace -maxdepth 1 -type d -name '*_service' 2>/dev/null || true; } | wc -l | tr -d '[:space:]')"
if [ "${fake_userspace}" -ne 0 ]; then
    fail_with "src/userspace/*_service directory present; userland belongs under userland/capsule_*"
    find src/userspace -maxdepth 1 -type d -name '*_service' >&2
else
    note ok "no fake src/userspace/*_service directories"
fi

# `src/drivers/` is the kernel-resident hardware-primitive surface.
# It carries only the bus enumerator and validators that the broker
# consumes, plus the boot-only RNG path. Every other driver lives in
# userland under `userland/capsule_driver_*`. Reintroducing a
# kernel-resident driver tree here fails the gate.
unexpected_drivers="$( { ls -1 src/drivers 2>/dev/null || true; } | grep -vE '^(pci|security|virtio_rng|mod\.rs)$' || true)"
if [ -n "${unexpected_drivers}" ]; then
    fail_with "src/drivers/ contains unexpected entries; only pci/security/virtio_rng are allowed"
    printf '%s\n' "${unexpected_drivers}" >&2
else
    note ok "src/drivers/ contains only pci/security/virtio_rng"
fi

# `src/services/` may only contain `caps`, `lifecycle`, `registry`.
# Anything else is a regression toward in-kernel services.
unexpected_services="$( { ls -1 src/services 2>/dev/null || true; } | grep -vE '^(caps|lifecycle|mod\.rs|registry\.rs)$' || true)"
if [ -n "${unexpected_services}" ]; then
    fail_with "src/services/ contains unexpected entries; only caps/lifecycle/registry are allowed"
    printf '%s\n' "${unexpected_services}" >&2
else
    note ok "src/services/ contains only caps/lifecycle/registry"
fi

# Production init must not reference deleted monolithic roots. The
# files below run on the trusted boot path; any string match against
# a deleted root means the init code is reaching back into the legacy
# tree. Match `crate::<root>::` to avoid false positives in comments
# that mention a name without invoking it.
init_files="src/nonos_main.rs \
src/boot/main/core_init.rs \
src/boot/main/mod.rs \
src/boot/main/mode.rs \
src/kernel_core/init/entry.rs \
src/kernel_core/init/framebuffer.rs \
src/kernel_core/init/memory.rs \
src/kernel_core/init/mod.rs \
src/userspace/init/entry.rs \
src/userspace/init/mod.rs \
src/userspace/init/capsule_boot.rs \
src/userspace/init/supervisor/mod.rs \
src/userspace/init/supervisor/loop_impl.rs"
forbidden_pattern='crate::(agents|apps|daemon|display|graphics|input|lang|locale|modules|monitor|network|nox|npkg|persistence|runtime|sdk|shell|storage|tty|vault|zk_engine|zksync)::|crate::services::[a-z0-9_]+_engine::|crate::syscall::(extended|aio|splice|bpf|ptrace|robust_futex|rseq|seccomp|mqueue|namespace|pkey|process_vm|xattr|fanotify|vdso|cgroup|capsule|keyring|graphics_surface)::'
init_dirty="$( { grep -nE "${forbidden_pattern}" ${init_files} 2>/dev/null || true; } )"
if [ -n "${init_dirty}" ]; then
    fail_with "production init references a deleted root"
    printf '%s\n' "${init_dirty}" >&2
else
    note ok "production init free of deleted-root references"
fi

# IPC lifecycle gates. The service endpoint table and the inbox
# registry are the kernel's only two places where capsule identity
# resolves to a destination. Direct mutation outside their owner
# module bypasses the exit-teardown unregister hooks
# (`unregister_endpoints_for_pid`, `unregister_for_pid`), so a buggy
# call site could leak a dead pid into routing.
endpoints_leak="$( { grep -rn 'ENDPOINTS\.' src --include='*.rs' || true; } | { grep -v '^src/services/registry.rs:' || true; } )"
if [ -n "${endpoints_leak}" ]; then
    fail_with "ENDPOINTS table touched outside src/services/registry.rs; only the registry module may mutate it"
    printf '%s\n' "${endpoints_leak}" >&2
else
    note ok "no direct endpoint table mutation outside services::registry"
fi

inbox_leak="$( { grep -rn 'REGISTRY\.write()\|REGISTRY\.read()' src/ipc --include='*.rs' || true; } | { grep -v '^src/ipc/nonos_inbox/' || true; } )"
if [ -n "${inbox_leak}" ]; then
    fail_with "inbox REGISTRY touched outside src/ipc/nonos_inbox/; only that module may mutate it"
    printf '%s\n' "${inbox_leak}" >&2
else
    note ok "no direct inbox table mutation outside ipc::nonos_inbox"
fi

# Every capsule client must round-trip through
# `services::lifecycle::transport::round_trip`. That helper is the
# single place that captures + re-checks generation between send and
# dequeue, so a client that touches the inbox surface directly is
# bypassing the stale-reply check.
client_bypass="$( { grep -rn 'nonos_inbox::try_enqueue\|nonos_inbox::try_dequeue\|nonos_inbox::try_enqueue_strict\|nonos_inbox::try_dequeue_existing' src/security src/fs --include='*.rs' || true; } )"
if [ -n "${client_bypass}" ]; then
    fail_with "capsule client bypassing services::lifecycle::transport::round_trip"
    printf '%s\n' "${client_bypass}" >&2
else
    note ok "no capsule client IPC round-trip bypasses lifecycle::transport"
fi

# Strict registration policy. The legacy auto-registering surface
# (`try_enqueue`, `dequeue`, `enqueue_with_timeout`) is gone; the
# only inbox-creation paths now are `register_inbox(name, owner)`
# (capsule-owned) and `register_or_get_bootstrap_inbox(name)`
# (kernel-owned). Any reintroduction fails the gate.
auto_register_calls="$( { grep -rEn 'nonos_inbox::(try_enqueue|dequeue|enqueue_with_timeout)\b' src --include='*.rs' || true; } | { grep -v 'try_enqueue_strict\|try_dequeue_existing' || true; } )"
if [ -n "${auto_register_calls}" ]; then
    fail_with "auto-registering inbox API reintroduced; use try_enqueue_strict / try_dequeue_existing"
    printf '%s\n' "${auto_register_calls}" >&2
else
    note ok "no auto-registering inbox calls outside the strict surface"
fi

# Bootstrap-only auto-register lives only in the spawn pipeline. A
# normal IPC path that calls it would resurrect the phantom-queue
# class of bugs.
bootstrap_callers="$( { grep -rn 'register_or_get_bootstrap_inbox' src --include='*.rs' || true; } | { grep -v '^src/ipc/nonos_inbox/' || true; } | { grep -v '^src/kernel_core/process_spawn/capsule_spawn/' || true; } )"
if [ -n "${bootstrap_callers}" ]; then
    fail_with "register_or_get_bootstrap_inbox called outside capsule_spawn"
    printf '%s\n' "${bootstrap_callers}" >&2
else
    note ok "register_or_get_bootstrap_inbox confined to spawn pipeline"
fi

# Local-only TLB invalidation must stay inside the paging manager
# and its arch backends. Once the SMP shootdown wrapper lands
# (`flush_tlb_one_smp` etc.), this baseline is the migration target:
# every caller that issues a local-only `invlpg` becomes a candidate
# for the cross-CPU variant. A new caller outside the listed paths
# is a silent local flush that would skip cross-CPU invalidation
# the moment APs go live, so the count is shrink-only.
tlb_local_callers="$( { grep -rn 'tlb::invalidate_page\|tlb::invalidate_all' src --include='*.rs' || true; } | { grep -v '^src/memory/paging/' || true; } | { grep -v '^src/arch/' || true; } | wc -l | tr -d '[:space:]')"
run_baseline 'tlb::invalidate_* callers outside paging/arch' "${baselines_dir}/tlb-local-callers.txt" "${tlb_local_callers}"

# Driver capsule isolation. The userland virtio-rng driver capsule
# must reach hardware only through the broker. Pulling kernel
# driver modules in (`crate::drivers::*`) would defeat the
# capsule trust boundary; the capsule lives in `userland/` and
# Rust path resolution makes the import meaningless anyway, but
# a typo or copy-pasted import would leak intent into the source
# tree. Catch it at the gate.
capsule_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_virtio_rng --include='*.rs' || true; } )"
if [ -n "${capsule_kernel_drivers}" ]; then
    fail_with "capsule_driver_virtio_rng must not import crate::drivers"
    printf '%s\n' "${capsule_kernel_drivers}" >&2
else
    note ok "capsule_driver_virtio_rng does not import kernel drivers"
fi

# Same isolation discipline for capsule_driver_virtio_blk. The
# block driver capsule must reach hardware only through broker
# syscalls; pulling kernel driver modules or kernel memory paths
# in would defeat the capsule trust boundary. The greps run
# against the source tree so a stray import is caught at the gate
# even though Rust path resolution would refuse it at compile
# time.
blk_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_virtio_blk --include='*.rs' || true; } )"
if [ -n "${blk_kernel_drivers}" ]; then
    fail_with "capsule_driver_virtio_blk must not import crate::drivers"
    printf '%s\n' "${blk_kernel_drivers}" >&2
else
    note ok "capsule_driver_virtio_blk does not import kernel drivers"
fi
unset blk_kernel_drivers

blk_kernel_mem="$( { grep -rEn 'crate::(memory|paging|phys|hardware)' userland/capsule_driver_virtio_blk --include='*.rs' || true; } )"
if [ -n "${blk_kernel_mem}" ]; then
    fail_with "capsule_driver_virtio_blk must not import kernel memory/paging/phys/hardware paths"
    printf '%s\n' "${blk_kernel_mem}" >&2
else
    note ok "capsule_driver_virtio_blk free of kernel memory/paging imports"
fi
unset blk_kernel_mem

# Legacy virtio-blk supported PIO; the capsule path is MMIO-only
# because port-grants are not part of this slice. A stray inline
# `in`/`out` would either fault on user CPL or, worse, slip past
# the broker. Catch any inline asm with port mnemonics.
blk_pio_asm="$( { grep -rEn 'asm!\([^)]*\b(inb|outb|inw|outw|inl|outl|in[[:space:]]|out[[:space:]])' userland/capsule_driver_virtio_blk --include='*.rs' || true; } )"
if [ -n "${blk_pio_asm}" ]; then
    fail_with "capsule_driver_virtio_blk must not use PIO asm; this slice is MMIO-only"
    printf '%s\n' "${blk_pio_asm}" >&2
else
    note ok "capsule_driver_virtio_blk free of PIO inline asm"
fi
unset blk_pio_asm

# No silent dead code in the new driver surface.
blk_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_driver_virtio_blk --include='*.rs' || true; } )"
if [ -n "${blk_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in capsule_driver_virtio_blk; remove it or add a written reason"
    printf '%s\n' "${blk_dead_code}" >&2
else
    note ok "capsule_driver_virtio_blk free of #[allow(dead_code)]"
fi
unset blk_dead_code

# Setup-phase rollback. Every setup/* file that performs a broker
# call past `claim` must also unwind every prior grant on a
# failure path. The check below requires each of the three later
# phases (mmio/irq/dma) to issue the broker release/unmap/unbind
# calls for the prior phases — a missing rollback is caught
# lexically.
for phase_file in \
    userland/capsule_driver_virtio_blk/src/setup/mmio.rs:mk_device_release \
    userland/capsule_driver_virtio_blk/src/setup/irq.rs:mk_mmio_unmap \
    userland/capsule_driver_virtio_blk/src/setup/dma.rs:mk_irq_unbind ; do
    file="${phase_file%%:*}"
    needle="${phase_file##*:}"
    if [ ! -f "${file}" ]; then
        fail_with "missing ${file}"
    elif ! grep -q "${needle}" "${file}"; then
        fail_with "${file} must roll back via ${needle} on failure"
    fi
done
note ok "capsule_driver_virtio_blk setup phases roll back prior broker grants"

# Endpoint string is the contract a kernel-side client opens
# against. Marker line in `main.rs` and the comment in
# `protocol/endpoint.rs` both have to spell `driver.virtio_blk0`
# the same way.
blk_endpoint_marker="$( { grep -rn 'driver\.virtio_blk0' userland/capsule_driver_virtio_blk --include='*.rs' || true; } )"
if [ -z "${blk_endpoint_marker}" ]; then
    fail_with "capsule_driver_virtio_blk does not advertise endpoint string driver.virtio_blk0"
else
    note ok "capsule_driver_virtio_blk advertises endpoint driver.virtio_blk0"
fi
unset blk_endpoint_marker

# Same isolation discipline for capsule_driver_virtio_net. The
# network driver capsule must reach hardware only through broker
# syscalls; any pull of kernel driver/memory paths defeats the
# capsule trust boundary. The greps run against the source tree
# so a stray import is caught at the gate.
net_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_virtio_net --include='*.rs' || true; } )"
if [ -n "${net_kernel_drivers}" ]; then
    fail_with "capsule_driver_virtio_net must not import crate::drivers"
    printf '%s\n' "${net_kernel_drivers}" >&2
else
    note ok "capsule_driver_virtio_net does not import kernel drivers"
fi
unset net_kernel_drivers

net_kernel_mem="$( { grep -rEn 'crate::(memory|paging|phys|hardware)' userland/capsule_driver_virtio_net --include='*.rs' || true; } )"
if [ -n "${net_kernel_mem}" ]; then
    fail_with "capsule_driver_virtio_net must not import kernel memory/paging/phys/hardware paths"
    printf '%s\n' "${net_kernel_mem}" >&2
else
    note ok "capsule_driver_virtio_net free of kernel memory/paging imports"
fi
unset net_kernel_mem

net_pio_asm="$( { grep -rEn 'asm!\([^)]*\b(inb|outb|inw|outw|inl|outl|in[[:space:]]|out[[:space:]])' userland/capsule_driver_virtio_net --include='*.rs' || true; } )"
if [ -n "${net_pio_asm}" ]; then
    fail_with "capsule_driver_virtio_net must not use PIO asm; this slice is MMIO-only"
    printf '%s\n' "${net_pio_asm}" >&2
else
    note ok "capsule_driver_virtio_net free of PIO inline asm"
fi
unset net_pio_asm

net_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_driver_virtio_net --include='*.rs' || true; } )"
if [ -n "${net_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in capsule_driver_virtio_net; remove it or add a written reason"
    printf '%s\n' "${net_dead_code}" >&2
else
    note ok "capsule_driver_virtio_net free of #[allow(dead_code)]"
fi
unset net_dead_code

# Setup-phase rollback for the network driver. Same shape as the
# virtio_blk gate: each later phase has to issue the prior
# phase's release/unmap/unbind on failure.
for phase_file in \
    userland/capsule_driver_virtio_net/src/setup/mmio.rs:mk_device_release \
    userland/capsule_driver_virtio_net/src/setup/irq.rs:mk_mmio_unmap \
    userland/capsule_driver_virtio_net/src/setup/dma.rs:mk_irq_unbind ; do
    file="${phase_file%%:*}"
    needle="${phase_file##*:}"
    if [ ! -f "${file}" ]; then
        fail_with "missing ${file}"
    elif ! grep -q "${needle}" "${file}"; then
        fail_with "${file} must roll back via ${needle} on failure"
    fi
done
note ok "capsule_driver_virtio_net setup phases roll back prior broker grants"

net_endpoint_marker="$( { grep -rn 'driver\.virtio_net0' userland/capsule_driver_virtio_net --include='*.rs' || true; } )"
if [ -z "${net_endpoint_marker}" ]; then
    fail_with "capsule_driver_virtio_net does not advertise endpoint string driver.virtio_net0"
else
    note ok "capsule_driver_virtio_net advertises endpoint driver.virtio_net0"
fi
unset net_endpoint_marker

# Same isolation discipline for capsule_driver_e1000. The Intel
# e1000 driver capsule reaches hardware only through broker
# syscalls; the kernel mirror at src/hardware/e1000_capsule
# never speaks PCI directly. Any pull of kernel driver / memory
# paths defeats the capsule trust boundary.
e1000_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_e1000 --include='*.rs' || true; } )"
if [ -n "${e1000_kernel_drivers}" ]; then
    fail_with "capsule_driver_e1000 must not import crate::drivers"
    printf '%s\n' "${e1000_kernel_drivers}" >&2
else
    note ok "capsule_driver_e1000 does not import kernel drivers"
fi
unset e1000_kernel_drivers

e1000_kernel_mem="$( { grep -rEn 'crate::(memory|paging|phys|hardware)' userland/capsule_driver_e1000 --include='*.rs' || true; } )"
if [ -n "${e1000_kernel_mem}" ]; then
    fail_with "capsule_driver_e1000 must not import kernel memory/paging/phys/hardware paths"
    printf '%s\n' "${e1000_kernel_mem}" >&2
else
    note ok "capsule_driver_e1000 free of kernel memory/paging imports"
fi
unset e1000_kernel_mem

e1000_pio_asm="$( { grep -rEn 'asm!\([^)]*\b(inb|outb|inw|outw|inl|outl|in[[:space:]]|out[[:space:]])' userland/capsule_driver_e1000 --include='*.rs' || true; } )"
if [ -n "${e1000_pio_asm}" ]; then
    fail_with "capsule_driver_e1000 must not use PIO asm; this driver is MMIO-only"
    printf '%s\n' "${e1000_pio_asm}" >&2
else
    note ok "capsule_driver_e1000 free of PIO inline asm"
fi
unset e1000_pio_asm

e1000_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_driver_e1000 --include='*.rs' || true; } )"
if [ -n "${e1000_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in capsule_driver_e1000; remove it or add a written reason"
    printf '%s\n' "${e1000_dead_code}" >&2
else
    note ok "capsule_driver_e1000 free of #[allow(dead_code)]"
fi
unset e1000_dead_code

for phase_file in \
    userland/capsule_driver_e1000/src/setup/mmio.rs:mk_device_release \
    userland/capsule_driver_e1000/src/setup/irq.rs:mk_mmio_unmap \
    userland/capsule_driver_e1000/src/setup/dma.rs:rollback ; do
    file="${phase_file%%:*}"
    needle="${phase_file##*:}"
    if [ ! -f "${file}" ]; then
        fail_with "missing ${file}"
    elif ! grep -q "${needle}" "${file}"; then
        fail_with "${file} must roll back via ${needle} on failure"
    fi
done
note ok "capsule_driver_e1000 setup phases roll back prior broker grants"

e1000_endpoint_marker="$( { grep -rn 'driver\.e1000_0' userland/capsule_driver_e1000 --include='*.rs' || true; } )"
if [ -z "${e1000_endpoint_marker}" ]; then
    fail_with "capsule_driver_e1000 does not advertise endpoint string driver.e1000_0"
else
    note ok "capsule_driver_e1000 advertises endpoint driver.e1000_0"
fi
unset e1000_endpoint_marker

# Per-capsule production kernel build path. Every verified capsule
# must declare a `microkernel-<slug>` Cargo feature and a matching
# `nonos-mk-<slug>-prod` Makefile recipe. The smoketest profile may
# remain alongside but cannot be the only kernel build path. Any
# obsolete hand-written `nonos-mk-<slug>:` override (without the
# `-prod` or `-test` suffix) is rejected because the macro at
# nonos-mk/capsule.mk owns that target name as the userland-ELF
# builder; an override silently breaks the trust-chain workflow's
# scratch-ceremony loop.
prod_missing=
prod_overrides=
for slug in proof-io ramfs keyring entropy crypto vfs market \
            driver-virtio-rng driver-virtio-blk driver-virtio-net \
            driver-ps2-input driver-xhci driver-e1000 ; do
    if ! grep -qE "^microkernel-${slug} = \[" Cargo.toml; then
        prod_missing="${prod_missing} microkernel-${slug}(feature)"
    fi
    if ! grep -qE "^nonos-mk-${slug}-prod:" Makefile; then
        prod_missing="${prod_missing} nonos-mk-${slug}-prod(target)"
    fi
    if grep -qE "^nonos-mk-${slug}:" Makefile; then
        prod_overrides="${prod_overrides} nonos-mk-${slug}"
    fi
done
if [ -n "${prod_missing}" ]; then
    fail_with "verified capsule(s) missing production build path:${prod_missing}"
fi
if [ -n "${prod_overrides}" ]; then
    fail_with "obsolete hand-written kernel-build override(s) shadowing the macro target:${prod_overrides}"
fi
if [ -z "${prod_missing}" ] && [ -z "${prod_overrides}" ]; then
    note ok "every verified capsule has a microkernel-<slug> feature + nonos-mk-<slug>-prod recipe; macro owns nonos-mk-<slug>"
fi
unset prod_missing prod_overrides

# Same isolation discipline for capsule_driver_ps2_input. The PS/2
# keyboard driver capsule must reach hardware only through the
# broker syscalls; any pull of kernel driver/memory paths defeats
# the capsule trust boundary.
ps2_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_ps2_input --include='*.rs' || true; } )"
if [ -n "${ps2_kernel_drivers}" ]; then
    fail_with "capsule_driver_ps2_input must not import crate::drivers"
    printf '%s\n' "${ps2_kernel_drivers}" >&2
else
    note ok "capsule_driver_ps2_input does not import kernel drivers"
fi
unset ps2_kernel_drivers

ps2_kernel_mem="$( { grep -rEn 'crate::(memory|paging|phys|hardware)' userland/capsule_driver_ps2_input --include='*.rs' || true; } )"
if [ -n "${ps2_kernel_mem}" ]; then
    fail_with "capsule_driver_ps2_input must not import kernel memory/paging/phys/hardware paths"
    printf '%s\n' "${ps2_kernel_mem}" >&2
else
    note ok "capsule_driver_ps2_input free of kernel memory/paging imports"
fi
unset ps2_kernel_mem

# Userland must talk to the i8042 only through `mk_pio_read` /
# `mk_pio_write`. Any inline `in`/`out` would skip the kernel
# mediator's grant-bounds check and the stale-epoch crosscheck,
# which is the entire point of MkPioGrant.
ps2_pio_asm="$( { grep -rEn 'asm!\([^)]*\b(inb|outb|inw|outw|inl|outl|in[[:space:]]|out[[:space:]])' userland/capsule_driver_ps2_input --include='*.rs' || true; } )"
if [ -n "${ps2_pio_asm}" ]; then
    fail_with "capsule_driver_ps2_input must not use raw PIO asm; use mk_pio_read / mk_pio_write"
    printf '%s\n' "${ps2_pio_asm}" >&2
else
    note ok "capsule_driver_ps2_input free of raw PIO inline asm"
fi
unset ps2_pio_asm

ps2_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_driver_ps2_input --include='*.rs' || true; } )"
if [ -n "${ps2_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in capsule_driver_ps2_input; remove it or add a written reason"
    printf '%s\n' "${ps2_dead_code}" >&2
else
    note ok "capsule_driver_ps2_input free of #[allow(dead_code)]"
fi
unset ps2_dead_code

# Setup-phase rollback for the PS/2 driver. Same shape as the
# virtio gates: each later phase has to issue the prior phase's
# release on failure so the broker is never left holding a
# partial setup.
for phase_file in \
    userland/capsule_driver_ps2_input/src/setup/pio.rs:mk_device_release \
    userland/capsule_driver_ps2_input/src/setup/irq.rs:mk_pio_release ; do
    file="${phase_file%%:*}"
    needle="${phase_file##*:}"
    if [ ! -f "${file}" ]; then
        fail_with "missing ${file}"
    elif ! grep -q "${needle}" "${file}"; then
        fail_with "${file} must roll back via ${needle} on failure"
    fi
done
note ok "capsule_driver_ps2_input setup phases roll back prior broker grants"

ps2_endpoint_marker="$( { grep -rn 'driver\.ps2_kbd0' userland/capsule_driver_ps2_input --include='*.rs' src/hardware/ps2_kbd_capsule --include='*.rs' || true; } )"
if [ -z "${ps2_endpoint_marker}" ]; then
    fail_with "capsule_driver_ps2_input does not advertise endpoint string driver.ps2_kbd0"
else
    note ok "capsule_driver_ps2_input advertises endpoint driver.ps2_kbd0"
fi
unset ps2_endpoint_marker

# capsule_driver_xhci must reach hardware only through broker
# syscalls. Same isolation gates as the virtio capsules: no kernel
# imports, no inline asm, no raw PIO, no #[allow(dead_code)],
# setup phases roll back, endpoint string advertised.
xhci_kernel_drivers="$( { grep -rn 'crate::drivers' userland/capsule_driver_xhci --include='*.rs' || true; } )"
if [ -n "${xhci_kernel_drivers}" ]; then
    fail_with "capsule_driver_xhci must not import crate::drivers"
    printf '%s\n' "${xhci_kernel_drivers}" >&2
else
    note ok "capsule_driver_xhci does not import kernel drivers"
fi
unset xhci_kernel_drivers

xhci_kernel_mem="$( { grep -rEn 'crate::(memory|paging|phys|hardware)' userland/capsule_driver_xhci --include='*.rs' || true; } )"
if [ -n "${xhci_kernel_mem}" ]; then
    fail_with "capsule_driver_xhci must not import kernel memory/paging/phys/hardware paths"
    printf '%s\n' "${xhci_kernel_mem}" >&2
else
    note ok "capsule_driver_xhci free of kernel memory/paging imports"
fi
unset xhci_kernel_mem

xhci_pio_asm="$( { grep -rEn 'asm!\([^)]*\b(inb|outb|inw|outw|inl|outl|in[[:space:]]|out[[:space:]])' userland/capsule_driver_xhci --include='*.rs' || true; } )"
if [ -n "${xhci_pio_asm}" ]; then
    fail_with "capsule_driver_xhci must not use raw PIO asm; xHCI is MMIO-only"
    printf '%s\n' "${xhci_pio_asm}" >&2
else
    note ok "capsule_driver_xhci free of raw PIO inline asm"
fi
unset xhci_pio_asm

xhci_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_driver_xhci --include='*.rs' || true; } )"
if [ -n "${xhci_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in capsule_driver_xhci"
    printf '%s\n' "${xhci_dead_code}" >&2
else
    note ok "capsule_driver_xhci free of #[allow(dead_code)]"
fi
unset xhci_dead_code

# Bring-up phases prior to BrokerHandles construction must roll
# back explicitly: mmio_map releases the device claim, irq_bind
# unmaps mmio + releases the claim. After BrokerHandles, RAII
# Drop chain handles the rest.
for phase_file in \
    userland/capsule_driver_xhci/src/setup/mmio_map.rs:mk_device_release \
    userland/capsule_driver_xhci/src/setup/irq_bind.rs:mk_mmio_unmap ; do
    file="${phase_file%%:*}"
    needle="${phase_file##*:}"
    if [ ! -f "${file}" ]; then
        fail_with "missing ${file}"
    elif ! grep -q "${needle}" "${file}"; then
        fail_with "${file} must roll back via ${needle} on failure"
    fi
done
note ok "capsule_driver_xhci pre-RAII setup phases roll back prior broker grants"

xhci_endpoint_marker="$( { grep -rn 'driver\.xhci0' userland/capsule_driver_xhci --include='*.rs' src/hardware/xhci_capsule --include='*.rs' || true; } )"
if [ -z "${xhci_endpoint_marker}" ]; then
    fail_with "capsule_driver_xhci does not advertise endpoint string driver.xhci0"
else
    note ok "capsule_driver_xhci advertises endpoint driver.xhci0"
fi
unset xhci_endpoint_marker

# Spawning the driver capsule on the default boot path would put
# it on every kernel image regardless of feature flag. The spawn
# call must stay behind the `nonos-capsule-driver-virtio-rng`
# feature gate; the gate-test below greps the init module to
# confirm the call is cfg-guarded.
spawn_call_unguarded="$(awk '
    /^[[:space:]]*#\[cfg\(feature = "nonos-capsule-driver-virtio-rng"\)\]/ { guarded = 1; next }
    /spawn_driver_virtio_rng_capsule\(\)/ {
        if (!guarded) print FILENAME ":" NR ": " $0
        guarded = 0
        next
    }
    /^[[:space:]]*$/ { next }
    { guarded = 0 }
' src/userspace/init/entry.rs)"
if [ -n "${spawn_call_unguarded}" ]; then
    fail_with "spawn_driver_virtio_rng_capsule must be cfg-guarded"
    printf '%s\n' "${spawn_call_unguarded}" >&2
else
    note ok "driver-virtio-rng spawn call gated on its feature flag"
fi

# Broker-controlled MMIO mapping. `map_user_mmio` / `unmap_user_mmio`
# are the helpers that install device physical memory into a user
# address space. The hardware broker is the only caller; any other
# call site is a bypass of claim/grant validation and turns the
# helper into a generic "map physical address" syscall.
mmio_helper_callers="$( { grep -rn 'map_user_mmio\|unmap_user_mmio' src --include='*.rs' || true; } | { grep -v '^src/memory/paging/' || true; } | { grep -v '^src/hardware/broker/' || true; } )"
if [ -n "${mmio_helper_callers}" ]; then
    fail_with "map_user_mmio / unmap_user_mmio called outside the hardware broker"
    printf '%s\n' "${mmio_helper_callers}" >&2
else
    note ok "user MMIO mapping helpers confined to the hardware broker"
fi

# `MkMmioMap` / `MkMmioUnmap` syscall handlers. The numeric router
# (`syscall::microkernel::dispatch`) and the broker's MMIO handlers
# are the only legitimate sites for these symbols. Anything else is
# a parallel handler that would skip the claim/grant gates.
mmio_handler_leak="$( { grep -rn 'sys_mmio_map\|sys_mmio_unmap\|MkMmioMap\|MkMmioUnmap' src --include='*.rs' || true; } | { grep -v '^src/syscall/microkernel/' || true; } | { grep -v '^src/syscall/contract/cap_table/mk.rs:' || true; } | { grep -v '^src/syscall/dispatch/' || true; } | { grep -v '^src/syscall/numbers/' || true; } | { grep -v '^src/syscall/abi/' || true; } | { grep -v '^src/syscall/tests/' || true; } | { grep -v '^src/hardware/broker/' || true; } )"
if [ -n "${mmio_handler_leak}" ]; then
    fail_with "MkMmioMap / MkMmioUnmap referenced outside the syscall and broker layers"
    printf '%s\n' "${mmio_handler_leak}" >&2
else
    note ok "MkMmioMap / MkMmioUnmap confined to syscall/broker"
fi

# Capability split for the driver-broker syscalls. `MkMmioMap` and
# `MkMmioUnmap` must route through `can_mmio()`; `MkDeviceClaim` /
# `MkDeviceRelease` through `can_driver()`; only `MkDeviceList` may
# share the old `can_device_enum()`. The cap_table::mk module is
# the single source of truth, so the gate inspects that file
# directly.
mk_table='src/syscall/contract/cap_table/mk.rs'
if [ ! -f "${mk_table}" ]; then
    fail_with "missing ${mk_table}"
elif ! grep -qE 'MkMmioMap[^=]*\|[^=]*MkMmioUnmap[^=]*=>[[:space:]]*caps\.can_mmio\(\)' "${mk_table}"; then
    fail_with "MkMmioMap / MkMmioUnmap must be gated by can_mmio()"
elif ! grep -qE 'MkDeviceClaim[^=]*\|[^=]*MkDeviceRelease[^=]*=>[[:space:]]*caps\.can_driver\(\)' "${mk_table}"; then
    fail_with "MkDeviceClaim / MkDeviceRelease must be gated by can_driver()"
elif grep -qE 'MkMmio(Map|Unmap)[^=]*=>[[:space:]]*caps\.can_device_enum\(\)' "${mk_table}"; then
    fail_with "MkMmioMap / MkMmioUnmap must not be gated by can_device_enum()"
elif ! grep -qE 'MkIrq(Bind|Unbind|Ack|Poll)[^=]*=>[[:space:]]*caps\.can_irq\(\)' "${mk_table}"; then
    fail_with "MkIrq* must be gated by can_irq()"
elif grep -qE 'MkIrq(Bind|Unbind|Ack|Poll)[^=]*=>[[:space:]]*caps\.can_(device_enum|driver|mmio|dma)\(\)' "${mk_table}"; then
    fail_with "MkIrq* must not be gated by can_device_enum / can_driver / can_mmio / can_dma"
elif ! grep -qE 'MkDma(Map|Unmap)[^=]*=>[[:space:]]*caps\.can_dma\(\)' "${mk_table}"; then
    fail_with "MkDma* must be gated by can_dma()"
elif grep -qE 'MkDma(Map|Unmap)[^=]*=>[[:space:]]*caps\.can_(device_enum|driver|mmio|irq)\(\)' "${mk_table}"; then
    fail_with "MkDma* must not be gated by can_device_enum / can_driver / can_mmio / can_irq"
else
    note ok "driver-broker capability split: DeviceEnum / Driver / Mmio / Irq / Dma"
fi

# Driver-broker ABI documentation must exist and cover the surface.
abi_doc='docs/abi/driver_broker_abi.md'
if [ ! -f "${abi_doc}" ]; then
    fail_with "missing ${abi_doc}"
else
    abi_missing=
    for sym in MkDeviceList MkDeviceClaim MkDeviceRelease MkMmioMap MkMmioUnmap MmioMapOut \
               MkIrqBind MkIrqUnbind MkIrqAck MkIrqPoll IrqBindOut IrqPollOut \
               MkDmaMap MkDmaUnmap DmaMapOut; do
        if ! grep -q "${sym}" "${abi_doc}"; then
            abi_missing="${abi_missing} ${sym}"
        fi
    done
    if [ -n "${abi_missing}" ]; then
        fail_with "${abi_doc} missing required symbols:${abi_missing}"
    else
        note ok "driver-broker ABI doc covers Device + Mmio + Irq + Dma surface"
    fi
fi

# Broker-controlled IRQ binding. `program_route_external` is the
# IO-APIC entry the broker uses to install a redirection for a
# claim holder. Anything outside the broker calling it would
# bypass the claim/grant gates and turn it into an arbitrary
# interrupt installer.
irq_route_external="$( { grep -rn 'program_route_external' src --include='*.rs' || true; } | { grep -v '^src/arch/x86_64/interrupt/ioapic/' || true; } | { grep -v '^src/hardware/broker/irq/' || true; } )"
if [ -n "${irq_route_external}" ]; then
    fail_with "program_route_external called from outside the broker IRQ path"
    printf '%s\n' "${irq_route_external}" >&2
else
    note ok "broker IRQ routing confined to ioapic + broker::irq"
fi

# Hard-IRQ dispatcher is the path that runs with interrupts
# disabled. It is allowed to talk to the LAPIC EOI and the
# IO-APIC mask register (the only writes it makes), and to its
# own atomic slot fields. It must not call into IPC, the
# scheduler, paging, or any allocator. Any of these would
# introduce a sleeping or contended lock on a path that runs
# with IRQs off.
forbidden_in_dispatch='nonos_inbox::|services::registry::|kernel_ipc::|process::scheduler|paging::manager::|alloc::vec::|alloc::string::'
dispatch_misuse="$(grep -nE "${forbidden_in_dispatch}" src/hardware/broker/irq/dispatch.rs 2>/dev/null || true)"
if [ -n "${dispatch_misuse}" ]; then
    fail_with "broker IRQ dispatcher uses a path that is not hard-IRQ safe"
    printf '%s\n' "${dispatch_misuse}" >&2
else
    note ok "broker IRQ dispatcher path is hard-IRQ-safe"
fi

# Broker-controlled DMA mapping. `map_user_dma` / `unmap_user_dma`
# are the helpers that install a DMA-coherent buffer into a user
# address space. The hardware broker is the only legitimate
# caller; anything else turns the helper into an arbitrary
# physical-page exposer.
dma_helper_callers="$( { grep -rn 'map_user_dma\|unmap_user_dma' src --include='*.rs' || true; } | { grep -v '^src/memory/paging/' || true; } | { grep -v '^src/hardware/broker/' || true; } )"
if [ -n "${dma_helper_callers}" ]; then
    fail_with "map_user_dma / unmap_user_dma called outside the hardware broker"
    printf '%s\n' "${dma_helper_callers}" >&2
else
    note ok "user DMA mapping helpers confined to the hardware broker"
fi

# `paging::map_device_memory` predates the broker. It maps device
# pages into the kernel for TCB callers (apic, framebuffer, virtio
# driver-side primitives). User-facing MMIO mappings must go through
# `map_user_mmio` so they get the user bit, the broker grant record,
# and revocation. This gate keeps `map_device_memory` callers in the
# kernel TCB only (memory/paging itself, drivers, apic, virtio).
device_map_external="$( { grep -rn 'map_device_memory' src --include='*.rs' || true; } | { grep -v '^src/memory/paging/' || true; } | { grep -v '^src/memory/mmio/' || true; } | { grep -v '^src/drivers/' || true; } | { grep -v '^src/arch/x86_64/apic/' || true; } | { grep -v '^src/interrupts/' || true; } | { grep -v '^src/sys/serial' || true; } )"
if [ -n "${device_map_external}" ]; then
    fail_with "map_device_memory called from outside the kernel TCB; user-facing MMIO must go through the broker"
    printf '%s\n' "${device_map_external}" >&2
else
    note ok "map_device_memory callers confined to the kernel TCB"
fi

# Marketplace policy must not appear in the kernel image. The
# kernel knows manifests, capability grants, and broker
# primitives; NOX, pricing, marketplace URLs, dashboards, and
# token-launch language live in userland capsules
# (capsule_market, capsule_payment, capsule_installer). A grep
# over the full kernel tree catches a stray reference before it
# ships. Intentionally narrow patterns: bare `nox` is a legal
# kernel module identifier and is not flagged; what we refuse is
# specific marketplace-policy strings.
marketplace_kernel_terms='nox_receipt|/api/v1/marketplace|0xNOX|marketplace\.url|marketplace_url|publisher_payout|nox/usd|token[ _]launch|/dashboard'
marketplace_in_kernel="$( { grep -rEni "${marketplace_kernel_terms}" src --include='*.rs' || true; } )"
if [ -n "${marketplace_in_kernel}" ]; then
    fail_with "marketplace policy appearing in kernel; that surface lives in userland capsules"
    printf '%s\n' "${marketplace_in_kernel}" >&2
else
    note ok "kernel free of NOX-receipt / marketplace URL / dashboard references"
fi

# Unsigned marketplace ingest is feature-gated by Cargo: the
# `dev` module is not compiled at all unless `dev-fixture` is on,
# so a non-feature build cannot reach `load_unsigned` even by
# name. The cargo feature system is the actual enforcement; this
# grep catches a hand-rolled second entry point that would route
# around the gate. The expected hits are the two source files
# under `ingest/{dev,mod}.rs` (the gated definition and re-export)
# and `main.rs::seed_dev_fixture` which is itself attribute-gated.
unsigned_market_ingest="$( { grep -rn 'fn load_unsigned\b' userland/capsule_market --include='*.rs' || true; } | { grep -v '^userland/capsule_market/src/ingest/dev.rs:' || true; } )"
if [ -n "${unsigned_market_ingest}" ]; then
    fail_with "fn load_unsigned defined outside ingest/dev.rs"
    printf '%s\n' "${unsigned_market_ingest}" >&2
else
    note ok "unsigned marketplace ingest stays inside the dev-fixture module"
fi
unset unsigned_market_ingest

# Marketplace install_ready must AND together every check; an
# install promotion that skips index-signature verification, or
# accepts an empty package_url / publisher_signature, would
# launder an unverified install. The grep below pins the
# evaluator to the file that holds the AND chain.
checks_file='userland/capsule_market/src/install_ready/checks.rs'
if [ ! -f "${checks_file}" ]; then
    fail_with "missing ${checks_file}"
elif ! grep -qE 'install_ready[[:space:]]*=[[:space:]]*index_signature_valid' "${checks_file}"; then
    fail_with "install_ready must start with index_signature_valid in the AND chain"
elif ! grep -q 'package_url_present' "${checks_file}"; then
    fail_with "install_ready missing package_url_present check"
elif ! grep -q 'publisher_signature_present' "${checks_file}"; then
    fail_with "install_ready missing publisher_signature_present check"
elif ! grep -q 'validation_passed' "${checks_file}"; then
    fail_with "install_ready missing validation_passed check"
elif ! grep -q 'arch_match' "${checks_file}"; then
    fail_with "install_ready missing arch_match check"
elif ! grep -q 'kernel_abi_compatible' "${checks_file}"; then
    fail_with "install_ready missing kernel_abi_compatible check"
else
    note ok "install_ready AND-chain holds all required checks"
fi
unset checks_file

# No #[allow(dead_code)] in the marketplace surface. Production
# code there has no dead-code helpers; if a future codec or
# protocol field needs a reserved primitive, add it alongside the
# field, not pre-emptively. Pre-existing #[allow(dead_code)]
# elsewhere in the tree is tracked under the wider audit
# baseline; this gate is scoped to the marketplace slice.
market_dead_code="$( { grep -rn '#\[allow(dead_code)\]' userland/capsule_market userland/marketplace_abi --include='*.rs' || true; } )"
if [ -n "${market_dead_code}" ]; then
    fail_with "#[allow(dead_code)] in marketplace surface; remove or relocate the primitive to the field that needs it"
    printf '%s\n' "${market_dead_code}" >&2
else
    note ok "marketplace surface free of #[allow(dead_code)]"
fi
unset market_dead_code

# Marketplace capsules must not pull in cryptographic primitives
# directly. capsule_market verifies signatures by routing through
# capsule_crypto via the kernel's CryptoEd25519Verify syscall;
# any direct Ed25519 / curve25519 / RSA / ECDSA dependency in
# capsule_market's manifest would put the math on the wrong side
# of the trust boundary.
market_crypto_dep_terms='^[[:space:]]*(ed25519|curve25519|x25519|rsa|ecdsa|p256|secp|dalek)'
market_crypto_dep="$( { grep -iE "${market_crypto_dep_terms}" userland/capsule_market/Cargo.toml || true; } )"
if [ -n "${market_crypto_dep}" ]; then
    fail_with "capsule_market must not depend on a cryptographic primitive crate"
    printf '%s\n' "${market_crypto_dep}" >&2
else
    note ok "capsule_market deps free of direct cryptographic primitives"
fi
unset market_crypto_dep market_crypto_dep_terms

# Likewise marketplace_abi is a wire-form crate; it must not
# reach for crypto. The verifier interface lives in capsule_market
# behind the Verifier trait.
abi_crypto_dep="$( { grep -iE '^[[:space:]]*(ed25519|curve25519|x25519|rsa|ecdsa|p256|secp|dalek)' userland/marketplace_abi/Cargo.toml || true; } )"
if [ -n "${abi_crypto_dep}" ]; then
    fail_with "marketplace_abi must not depend on a cryptographic primitive crate"
    printf '%s\n' "${abi_crypto_dep}" >&2
else
    note ok "marketplace_abi deps free of direct cryptographic primitives"
fi
unset abi_crypto_dep

# CryptoEd25519Verify must route through the kernel-side crypto
# capsule client when the dispatch handler exists. The handler
# itself lands as part of an in-flight slice and is not yet on
# the baseline; the gate only enforces correct routing once the
# file is present, so it is a no-op on a baseline that has not
# pulled the slice in yet.
verify_handler='src/syscall/dispatch/crypto/verify.rs'
if [ -f "${verify_handler}" ]; then
    if ! grep -q 'crypto_capsule::client' "${verify_handler}"; then
        fail_with "CryptoEd25519Verify must route through crypto_capsule::client"
    elif grep -qE 'crate::crypto::(verify_signature|ed25519|sign_message)' "${verify_handler}"; then
        fail_with "CryptoEd25519Verify must not call kernel-resident crypto directly"
    else
        note ok "CryptoEd25519Verify routes through capsule_crypto"
    fi
else
    note ok "CryptoEd25519Verify dispatch handler not on this baseline (gate skipped)"
fi
unset verify_handler

# Host-side marketplace-index CLI must exist and be wired into
# the workspace. The binary is what an operator runs to encode
# and sign the canonical wire form; absence breaks the offline
# signing pipeline before the OS ever sees a blob.
if ! grep -q '^name = "marketplace-index"' nonos-mk/Cargo.toml; then
    fail_with "nonos-mk/Cargo.toml missing [[bin]] marketplace-index"
elif [ ! -f nonos-mk/src/main.rs ]; then
    fail_with "nonos-mk/src/main.rs missing"
else
    note ok "marketplace-index CLI declared and source present"
fi

# The CLI must encode through nonos_marketplace_abi, not by
# hand-rolling NOX0/JSON/fixed-trailer wire bytes. A grep for
# legacy wrapper magic in the tool source guards against the
# CLI drifting from the canonical codec.
mk_tool_drift="$( { grep -rnE 'b?"NOX0"|"index_signature":|fixed_trailer|trailer_v[0-9]' nonos-mk/src --include='*.rs' || true; } | { grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true; } )"
if [ -n "${mk_tool_drift}" ]; then
    fail_with "marketplace-index CLI must use nonos_marketplace_abi codec, not hand-rolled wrappers"
    printf '%s\n' "${mk_tool_drift}" >&2
else
    note ok "marketplace-index CLI free of NOX0/JSON/trailer drift"
fi
unset mk_tool_drift

# Operator pubkey trust list must compile in. The 0xNOX live
# operator pubkey baked here is the only key the marketplace
# capsule trusts in production; rotation requires a kernel image
# rebuild.
trust_keys='userland/capsule_market/src/bootstrap_trust/keys.rs'
if [ ! -f "${trust_keys}" ]; then
    fail_with "missing ${trust_keys} (operator trust list)"
elif ! grep -q '0x29, 0x5f, 0x84, 0xc9' "${trust_keys}"; then
    fail_with "0xNOX operator pubkey missing from bootstrap_trust"
else
    note ok "0xNOX operator pubkey baked into capsule_market trust list"
fi
unset trust_keys

boot_build='nonos-bootloader/build.rs'
if [ ! -f "${boot_build}" ]; then
    fail_with "missing ${boot_build}"
elif ! grep -q 'production bootloader requires NONOS_SIGNING_KEY' "${boot_build}"; then
    fail_with "bootloader production build must require NONOS_SIGNING_KEY"
elif ! grep -q 'production bootloader requires NONOS_ZK_CEREMONY_DIR' "${boot_build}"; then
    fail_with "bootloader production build must require NONOS_ZK_CEREMONY_DIR"
elif ! grep -q 'production bootloader requires signed ceremony VK' "${boot_build}"; then
    fail_with "bootloader production build must reject generated development VKs"
else
    note ok "bootloader production mode fails closed on signing key and ZK ceremony inputs"
fi
unset boot_build

boot_features='nonos-bootloader/Cargo.toml'
if ! grep -q '^hardened-production = \["production"\]' "${boot_features}"; then
    fail_with "nonos-bootloader missing hardened-production feature alias"
elif ! grep -q '^dev-qemu = \["dev-mode"\]' "${boot_features}"; then
    fail_with "nonos-bootloader missing dev-qemu feature alias"
else
    note ok "bootloader build modes are explicit"
fi
unset boot_features

firmware_sig='nonos-bootloader/src/firmware/validation/signature.rs'
firmware_sig_stub="$(grep -nE 'fn verify_(rsa|ecdsa|ed25519).*SignatureResult::Valid|=>[[:space:]]*SignatureResult::Valid' "${firmware_sig}" || true)"
if [ -n "${firmware_sig_stub}" ]; then
    fail_with "firmware signature validation must not return Valid outside real verifier success"
    printf '%s\n' "${firmware_sig_stub}" >&2
else
    note ok "firmware signature validation has no always-valid stub"
fi
unset firmware_sig firmware_sig_stub

rollback_path='nonos-bootloader/src/boot/crypto/rollback.rs'
entry_pipeline='nonos-bootloader/src/entry/pipeline.rs'
if ! grep -q 'update_kernel_version' "${rollback_path}"; then
    fail_with "bootloader rollback path must commit accepted kernel versions"
elif ! grep -q 'commit_rollback' "${entry_pipeline}"; then
    fail_with "boot entry pipeline must call commit_rollback after verified load"
else
    note ok "bootloader rollback state is checked and committed"
fi
unset rollback_path entry_pipeline

boot_mod_bodies="$(find nonos-bootloader/src -name mod.rs -type f -print0 | xargs -0 awk '
    BEGINFILE { block = 0 }
    /^[[:space:]]*\/\// || /^[[:space:]]*$/ { next }
    /^[[:space:]]*#\[/ { next }
    /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]+[[:space:]]*;/ { next }
    /^[[:space:]]*pub(\([^)]+\))?[[:space:]]+use[[:space:]]/ {
        if ($0 !~ /;[[:space:]]*$/) { block = 1 }
        next
    }
    block {
        if ($0 ~ /;[[:space:]]*$/) { block = 0 }
        next
    }
    { print FILENAME ":" FNR ": " $0 }
')"
if [ -n "${boot_mod_bodies}" ]; then
    fail_with "bootloader mod.rs files must only declare modules and re-export symbols"
    printf '%s\n' "${boot_mod_bodies}" >&2
else
    note ok "bootloader mod.rs files are export-only"
fi
unset boot_mod_bodies

boot_mod_oversize="$(find nonos-bootloader/src -name mod.rs -type f -print0 | xargs -0 wc -l | awk '$1 > 75 && $2 != "total" { print }')"
if [ -n "${boot_mod_oversize}" ]; then
    fail_with "bootloader mod.rs files must stay at or below 75 lines"
    printf '%s\n' "${boot_mod_oversize}" >&2
else
    note ok "bootloader mod.rs files stay under 75 lines"
fi
unset boot_mod_oversize

boot_entry_oversize="$(find nonos-bootloader/src/entry -name '*.rs' -type f -print0 | xargs -0 wc -l | awk '$1 > 75 && $2 != "total" { print }')"
if [ -n "${boot_entry_oversize}" ]; then
    fail_with "bootloader entry files must stay at or below 75 lines"
    printf '%s\n' "${boot_entry_oversize}" >&2
else
    note ok "bootloader entry files stay under 75 lines"
fi
unset boot_entry_oversize

boot_entry_comments="$(find nonos-bootloader/src/entry -name '*.rs' -type f -print0 | xargs -0 awk 'FNR > 15 && /\/\/|\/\*|\*\// { print FILENAME ":" FNR ": " $0 }')"
if [ -n "${boot_entry_comments}" ]; then
    fail_with "bootloader entry files must not carry inline comments outside the license header"
    printf '%s\n' "${boot_entry_comments}" >&2
else
    note ok "bootloader entry files carry no inline comments outside license headers"
fi
unset boot_entry_comments

kernel_verify_oversize="$(find nonos-bootloader/src/kernel_verify -name '*.rs' -type f -print0 | xargs -0 wc -l | awk '$1 > 75 && $2 != "total" { print }')"
if [ -n "${kernel_verify_oversize}" ]; then
    fail_with "kernel_verify files must stay at or below 75 lines"
    printf '%s\n' "${kernel_verify_oversize}" >&2
else
    note ok "kernel_verify files stay under 75 lines"
fi
unset kernel_verify_oversize

kernel_verify_comments="$(find nonos-bootloader/src/kernel_verify -name '*.rs' -type f -print0 | xargs -0 awk 'FNR > 15 && /\/\/|\/\*|\*\// { print FILENAME ":" FNR ": " $0 }')"
if [ -n "${kernel_verify_comments}" ]; then
    fail_with "kernel_verify files must not carry inline comments outside the license header"
    printf '%s\n' "${kernel_verify_comments}" >&2
else
    note ok "kernel_verify files carry no inline comments outside license headers"
fi
unset kernel_verify_comments

# `metadata_preview` is not an OS-side validation status. The
# canonical mapping is unknown=0/pending=1/validated=2/rejected=3;
# adding metadata_preview without a schema-version bump would
# collide with rejected=3 on the wire.
metadata_preview_leak="$( { grep -rn 'metadata_preview\|MetadataPreview' userland/marketplace_abi userland/capsule_market --include='*.rs' || true; } )"
if [ -n "${metadata_preview_leak}" ]; then
    fail_with "metadata_preview status appears in production marketplace surface; bump schema_version first"
    printf '%s\n' "${metadata_preview_leak}" >&2
else
    note ok "no metadata_preview enum value in production marketplace surface"
fi
unset metadata_preview_leak

# Capability strings on the wire must be canonical CapName
# constants from capsule_manifest.schema.json (CAP_IPC, CAP_VFS,
# ...). A lowercased capability in a fixture indicates someone
# hand-typed it; the installer must reject those, but the
# fixtures themselves must not lead with a typo.
lowercase_cap_leak="$( { grep -rEn '"cap_(ipc|memory|vfs|network|display|input|crypto|entropy|wallet_view|wallet_spend|persistence|update|hardware_broker)"' userland --include='*.rs' || true; } )"
if [ -n "${lowercase_cap_leak}" ]; then
    fail_with "lowercase capability strings in marketplace surface; production canon is uppercase CAP_*"
    printf '%s\n' "${lowercase_cap_leak}" >&2
else
    note ok "marketplace surface free of lowercase cap_* strings"
fi
unset lowercase_cap_leak

# Capsule integration matrix must exist and cover every userland
# crate that ships a Make target. The matrix is the single source
# of truth for "is this capsule build-only / embedded / spawned /
# client / smoke"; a Make target without an entry means a capsule
# is shipping without a documented integration state.
matrix='docs/production-roadmap/capsule_integration_matrix.md'
if [ ! -f "${matrix}" ]; then
    fail_with "missing ${matrix} (capsule integration matrix)"
else
    missing_capsule_rows=
    for cap_dir in userland/capsule_*; do
        [ -d "${cap_dir}" ] || continue
        cap_name="${cap_dir##*/}"
        if ! grep -q "${cap_dir}" "${matrix}"; then
            missing_capsule_rows="${missing_capsule_rows}${cap_name}\n"
        fi
    done
    if [ -n "${missing_capsule_rows}" ]; then
        fail_with "capsule(s) missing from integration matrix: $(printf '%b' "${missing_capsule_rows}")"
    else
        note ok "every userland capsule has a row in the integration matrix"
    fi
    unset missing_capsule_rows
fi
unset matrix

# Warning-suppression discipline. None of the production
# capsule surfaces below may carry an `#[allow(dead_code)]`,
# `#[allow(unused...)]`, or `#![allow(warnings)]` attribute;
# a real cleanup beats a silenced lint. capsule_crypto is on
# this list even while the in-flight Ed25519 slice is dirty —
# any temporary suppression in that branch must be removed
# before the slice merges.
warning_suppress_capsules="
    userland/capsule_ramfs
    userland/capsule_keyring
    userland/capsule_entropy
    userland/capsule_crypto
    userland/capsule_vfs
    userland/capsule_driver_virtio_rng
    userland/capsule_driver_virtio_blk
    userland/capsule_market
    userland/marketplace_abi
"
warning_suppress_hits=
for cap_dir in ${warning_suppress_capsules}; do
    [ -d "${cap_dir}" ] || continue
    hits="$( { grep -rnE '#!?\[allow\((dead_code|unused|warnings)' "${cap_dir}" --include='*.rs' || true; } )"
    if [ -n "${hits}" ]; then
        warning_suppress_hits="${warning_suppress_hits}${hits}
"
    fi
done
if [ -n "${warning_suppress_hits}" ]; then
    fail_with "production capsule(s) silence lints with #[allow(...)]; remove the suppression and fix the cause"
    printf '%s\n' "${warning_suppress_hits}" >&2
else
    note ok "production capsules free of #[allow(dead_code)] / unused / warnings suppressions"
fi
unset warning_suppress_hits warning_suppress_capsules

# Kernel feature ↔ kernel module pairing. A `nonos-capsule-<name>`
# feature in `Cargo.toml` must have a matching kernel-side module
# under `src/` that contains the embed/spawn glue, and vice
# versa. The pairing is verified directly against the source tree
# rather than against any external doc, so the gate stays
# enforceable without out-of-tree state.
declare_pair() {
    feature="$1"
    module_dir="$2"
    feature_present=0
    module_present=0
    grep -qE "^${feature} *=" Cargo.toml && feature_present=1 || true
    [ -d "${module_dir}" ] && module_present=1 || true
    if [ "${feature_present}" -ne "${module_present}" ]; then
        fail_with "${feature} (in Cargo.toml) and ${module_dir} (kernel module) must both be present or both be absent"
    fi
}
declare_pair nonos-capsule-ramfs              src/fs/ramfs_capsule
declare_pair nonos-capsule-keyring            src/security/keyring_capsule
declare_pair nonos-capsule-entropy            src/security/entropy_capsule
declare_pair nonos-capsule-crypto             src/security/crypto_capsule
declare_pair nonos-capsule-vfs                src/fs/vfs_capsule
declare_pair nonos-capsule-driver-virtio-rng  src/hardware/virtio_rng_capsule
declare_pair nonos-capsule-driver-virtio-blk  src/hardware/virtio_blk_capsule
declare_pair nonos-capsule-driver-virtio-net  src/hardware/virtio_net_capsule
declare_pair nonos-capsule-driver-e1000       src/hardware/e1000_capsule
declare_pair nonos-capsule-market             src/security/market_capsule
note ok "kernel feature flags match kernel module presence"
unset feature module_dir feature_present module_present
unset -f declare_pair

# Driver-capsule spawn-call cfg-guard. Driver capsules differ from
# the always-baseline capsules (ramfs/keyring/entropy/crypto/vfs)
# in that they probe real hardware: a baseline image without the
# device should not even attempt to spawn the driver. Only the
# `spawn_driver_*_capsule` helpers therefore need the feature
# guard at the call site. The virtio-rng case is checked in its
# own block above; this block fails if any new
# `spawn_driver_*_capsule()` call goes ungated.
unguarded_driver_spawns="$(awk '
    /^[[:space:]]*#\[cfg\(feature = "/ { guarded = 1; next }
    /spawn_driver_[a-z_]+_capsule\(\);?/ {
        if (!guarded) print FILENAME ":" NR ": " $0
        guarded = 0
        next
    }
    /^[[:space:]]*$/ { next }
    { guarded = 0 }
' src/userspace/init/entry.rs)"
if [ -n "${unguarded_driver_spawns}" ]; then
    fail_with "spawn_driver_*_capsule call without a preceding #[cfg(feature = \"...\")]"
    printf '%s\n' "${unguarded_driver_spawns}" >&2
else
    note ok "every spawn_driver_*_capsule call in init/entry.rs is feature-gated"
fi
unset unguarded_driver_spawns

# Asm-isolation. Every .S file must live under an arch tree; no
# inline assembly source files allowed in random kernel modules.
asm_outside_arch="$(find . -name '*.S' \
    -not -path '*/target/*' \
    -not -path '*/arch/*/asm/*' \
    -not -path '*/.claude/*' \
    -not -path '*/third_party/*' \
    2>/dev/null || true)"
if [ -n "${asm_outside_arch}" ]; then
    fail_with ".S files found outside src/arch/<arch>/asm/ trees"
    printf '%s\n' "${asm_outside_arch}" >&2
else
    note ok "no .S files outside arch trees"
fi
unset asm_outside_arch

# User-CR3 cleanliness. The address-space cloner must never write
# PML4[0]; user CR3s only carry the canonical kernel half
# (entries 256..511). A write at index 0 would leak the
# bootloader's identity survival window into every user task.
pml4_zero_writes="$(grep -RInE \
    'pml4[[:space:]]*\[[[:space:]]*0[[:space:]]*\][[:space:]]*=' \
    src/process/address_space src/memory/paging 2>/dev/null || true)"
if [ -n "${pml4_zero_writes}" ]; then
    fail_with "user-half address-space code writes PML4[0]; only the kernel-half clone (256..511) may run there"
    printf '%s\n' "${pml4_zero_writes}" >&2
else
    note ok "address-space cloners do not write PML4[0]"
fi
unset pml4_zero_writes

# User-half teardown stays inside PML4[0..256]. Kernel-half PDPTs
# at PML4[256..511] are seeded once from KERNEL_ASID and shared
# by every live address space; freeing them would corrupt all
# concurrent processes. The walker's loop bound and its
# const_assert lock that invariant.
teardown_src='src/memory/paging/manager/address_space/teardown.rs'
if [ ! -f "${teardown_src}" ]; then
    fail_with "missing ${teardown_src}"
elif ! grep -qE 'for[[:space:]]+i[[:space:]]+in[[:space:]]+0\.\.KERNEL_HALF_START' "${teardown_src}"; then
    fail_with "${teardown_src} must iterate PML4[0..KERNEL_HALF_START] only"
elif ! grep -qE 'KERNEL_HALF_START[[:space:]]*==[[:space:]]*256' "${teardown_src}"; then
    fail_with "${teardown_src} must compile-time assert KERNEL_HALF_START == 256"
elif grep -qE 'for[[:space:]]+[a-z_]+[[:space:]]+in[[:space:]]+(256\.\.|0\.\.512)' "${teardown_src}"; then
    fail_with "${teardown_src} must not iterate the kernel-half PML4 range"
else
    note ok "user-half teardown never iterates PML4[256..511]"
fi
unset teardown_src

# `cleanup_address_space` refuses KERNEL_ASID and routes through
# the structural walker. A direct `frame_alloc::deallocate_frame`
# on a non-PML4 frame here would skip subtable cleanup; the only
# permitted free in this file is the PML4 frame itself.
cleanup_src='src/memory/paging/manager/address_space/cleanup.rs'
if [ ! -f "${cleanup_src}" ]; then
    fail_with "missing ${cleanup_src}"
elif ! grep -qE 'asid[[:space:]]*==[[:space:]]*KERNEL_ASID' "${cleanup_src}"; then
    fail_with "${cleanup_src} must refuse KERNEL_ASID"
elif ! grep -qE 'teardown_user_half\(' "${cleanup_src}"; then
    fail_with "${cleanup_src} must walk the user half via teardown_user_half"
else
    note ok "cleanup_address_space refuses KERNEL_ASID and walks via teardown_user_half"
fi
unset cleanup_src

# `sys_munmap` must return frames to the allocator and update the
# per-pid mmap-VA state. The global `NEXT_USER_VA` cursor is gone:
# sys_mmap reserves out of the calling process's `pcb.mmap_va`,
# sys_munmap releases the same range. Catches a regression that
# returns to a global bump.
mmap_src='src/syscall/microkernel/memory.rs'
if [ ! -f "${mmap_src}" ]; then
    fail_with "missing ${mmap_src}"
elif grep -qE '\bNEXT_USER_VA\b' "${mmap_src}"; then
    fail_with "${mmap_src} reintroduced a global NEXT_USER_VA; reserve via pcb.mmap_va"
elif ! awk '/pub fn sys_mmap/,/^\}/' "${mmap_src}" | grep -qE 'reserve_va\(' ; then
    fail_with "${mmap_src} sys_mmap must reserve via the per-pid allocator"
elif ! awk '/pub fn sys_munmap/,/^\}/' "${mmap_src}" | grep -qE 'deallocate_frame\(' ; then
    fail_with "${mmap_src} sys_munmap must deallocate the unmapped frames"
elif ! awk '/pub fn sys_munmap/,/^\}/' "${mmap_src}" | grep -qE 'release_va\(' ; then
    fail_with "${mmap_src} sys_munmap must update per-pid mmap-VA state"
else
    note ok "sys_mmap/munmap reserve/release through pcb.mmap_va; no global VA cursor"
fi
unset mmap_src

# Boot path GDT: the active GDT must be the arch-local per-CPU
# BSP_GDT, not the legacy 3-entry sys::gdt. The bug class this
# guards: iretq into CPL=3 with USER_CS=0x23 / USER_DS=0x1B against
# a 24-byte GDT, which #GP'd with selector index outside limit.
core_init_legacy_gdt="$(grep -nE 'crate::sys::gdt|sys::gdt::|gdt::setup\b' src/boot/main/core_init.rs 2>/dev/null || true)"
if [ -n "${core_init_legacy_gdt}" ]; then
    fail_with "core_init.rs must use crate::arch::x86_64::gdt; legacy sys::gdt is dead"
    printf '%s\n' "${core_init_legacy_gdt}" >&2
else
    note ok "core_init.rs uses arch::x86_64::gdt (no legacy sys::gdt)"
fi
unset core_init_legacy_gdt

legacy_gdt_setup_callers="$(grep -RInE 'sys::gdt::setup|crate::sys::gdt::ops::setup' src --include='*.rs' 2>/dev/null || true)"
if [ -n "${legacy_gdt_setup_callers}" ]; then
    fail_with "legacy sys::gdt::ops::setup() still called from active source"
    printf '%s\n' "${legacy_gdt_setup_callers}" >&2
else
    note ok "legacy sys::gdt::setup has no active callers"
fi
unset legacy_gdt_setup_callers

# USER_CS / USER_DS / TSS must point inside the arch GDT.
gdt_struct="$(awk '/^pub struct Gdt \{/,/^\}/' src/arch/x86_64/gdt/table.rs)"
gdt_field_check_failed=0
for field in null kernel_code kernel_data user_data user_code tss; do
    if ! printf '%s' "${gdt_struct}" | grep -qE "pub ${field}:"; then
        fail_with "Gdt is missing field '${field}'; user selectors will overflow GDT limit"
        gdt_field_check_failed=1
    fi
done
if [ "${gdt_field_check_failed}" -eq 0 ]; then
    note ok "Gdt has null/kernel_*/user_*/tss fields covering selectors 0x00..0x28"
fi
unset gdt_struct gdt_field_check_failed

sel_user_data_def="$(grep -E '^pub const SEL_USER_DATA' src/arch/x86_64/gdt/constants.rs || true)"
sel_user_code_def="$(grep -E '^pub const SEL_USER_CODE' src/arch/x86_64/gdt/constants.rs || true)"
sel_tss_def="$(grep -E '^pub const SEL_TSS' src/arch/x86_64/gdt/constants.rs || true)"
if ! echo "${sel_user_data_def}" | grep -q '0x18 | 3'; then
    fail_with "SEL_USER_DATA must be 0x18 | 3 to land at GDT idx 3 RPL=3"
    printf '%s\n' "${sel_user_data_def}" >&2
fi
if ! echo "${sel_user_code_def}" | grep -q '0x20 | 3'; then
    fail_with "SEL_USER_CODE must be 0x20 | 3 to land at GDT idx 4 RPL=3"
    printf '%s\n' "${sel_user_code_def}" >&2
fi
if ! echo "${sel_tss_def}" | grep -q '0x28'; then
    fail_with "SEL_TSS must be 0x28 to land at GDT idx 5"
    printf '%s\n' "${sel_tss_def}" >&2
fi
note ok "user_data/user_code/tss selectors match the Gdt field layout"
unset sel_user_data_def sel_user_code_def sel_tss_def

# NØNOS userland syscall ABI: Mk* only. No Linux numbers, no
# compatibility shims, no stub wrappers in active libc.
libc_syscall_dir="userland/libc/src/syscall"

if [ ! -d "${libc_syscall_dir}" ]; then
    fail_with "libc syscall tree missing at ${libc_syscall_dir}"
else
    forbidden_lang="$(grep -RInE 'Linux-shape|compatibility numbers|linux_compat|[Ss]tub until' ${libc_syscall_dir} 2>/dev/null || true)"
    if [ -n "${forbidden_lang}" ]; then
        fail_with "active userland libc syscall files must not reference Linux-shape / compatibility / stub language"
        printf '%s\n' "${forbidden_lang}" >&2
    else
        note ok "userland libc syscall surface free of Linux-shape language"
    fi
    unset forbidden_lang

    leaked_values="$(grep -RInE '^[[:space:]]*pub(\([^)]*\))?[[:space:]]+const[[:space:]]+N_(READ|WRITE|RT_SIGRETURN|MMAP_LINUX|EXIT_LINUX)' ${libc_syscall_dir} 2>/dev/null || true)"
    leaked_values="${leaked_values}$(grep -RIn '^[[:space:]]*pub.*const[[:space:]]\+N_MMAP:[[:space:]]\+i64[[:space:]]\+=[[:space:]]\+9;' ${libc_syscall_dir} 2>/dev/null || true)"
    leaked_values="${leaked_values}$(grep -RIn '^[[:space:]]*pub.*const[[:space:]]\+N_EXIT:[[:space:]]\+i64[[:space:]]\+=[[:space:]]\+60;' ${libc_syscall_dir} 2>/dev/null || true)"
    if [ -n "${leaked_values}" ]; then
        fail_with "active userland libc must not declare Linux syscall values (read=0, write=1, mmap=9, rt_sigreturn=15, exit=60)"
        printf '%s\n' "${leaked_values}" >&2
    else
        note ok "userland libc has no Linux-value syscall constants"
    fi
    unset leaked_values

    libc_numbers="${libc_syscall_dir}/numbers/mod.rs"
    libc_mmap="$(grep -E '^pub(\([^)]*\))? const N_MK_MMAP: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    libc_exit="$(grep -E '^pub(\([^)]*\))? const N_MK_EXIT: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    libc_yield="$(grep -E '^pub(\([^)]*\))? const N_MK_YIELD: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    kern_mmap="$(grep -E '^pub const SYS_MMAP: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"
    kern_exit="$(grep -E '^pub const SYS_EXIT: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"
    kern_yield="$(grep -E '^pub const SYS_YIELD: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"

    abi_drift=0
    if [ "${libc_mmap}" != "${kern_mmap}" ]; then
        fail_with "ABI drift: libc N_MK_MMAP=${libc_mmap} vs kernel microkernel::SYS_MMAP=${kern_mmap}"
        abi_drift=1
    fi
    if [ "${libc_exit}" != "${kern_exit}" ]; then
        fail_with "ABI drift: libc N_MK_EXIT=${libc_exit} vs kernel microkernel::SYS_EXIT=${kern_exit}"
        abi_drift=1
    fi
    if [ "${libc_yield}" != "${kern_yield}" ]; then
        fail_with "ABI drift: libc N_MK_YIELD=${libc_yield} vs kernel microkernel::SYS_YIELD=${kern_yield}"
        abi_drift=1
    fi
    if [ "${abi_drift}" -eq 0 ]; then
        note ok "libc N_MK_MMAP / N_MK_EXIT / N_MK_YIELD match kernel microkernel::SYS_*"
    fi
    unset libc_numbers libc_mmap libc_exit libc_yield kern_mmap kern_exit kern_yield abi_drift
fi
unset libc_syscall_dir

# `pcb.caps_bits` is the only per-pid capability authority. The
# legacy `process::capabilities` directory carried a parallel
# `CapabilitySet` mirror plus a Linux-shape `Capability` enum that
# aliased the unified bit space. Both are deleted. The directory
# must not return.
if [ -d 'src/process/capabilities' ]; then
    fail_with "src/process/capabilities reappeared; pcb.caps_bits is the only per-pid authority"
elif grep -RInE 'use crate::process::capabilities::|process::capabilities::' src --include='*.rs' >/dev/null 2>&1; then
    fail_with "process::capabilities import resurfaced"
    grep -RInE 'use crate::process::capabilities::|process::capabilities::' src --include='*.rs' >&2
elif grep -RInE '\.caps\.lock\(\)' src --include='*.rs' >/dev/null 2>&1; then
    fail_with "pcb.caps.lock() reader/writer present; the parallel mirror is gone"
    grep -RInE '\.caps\.lock\(\)' src --include='*.rs' >&2
else
    note ok "process::capabilities module deleted; pcb.caps mirror has no callers"
fi

# IST trap substrate. Every IDT gate that calls `set_stack_index(N)`
# loads `TSS.IST[N]` on entry. If that slot is zero the CPU faults
# during trap delivery and triple-faults before any handler prints.
# The PerCpuGdt::init path must back every IST index the IDT uses.
ist_indices_used="$(grep -RIn 'set_stack_index' src/interrupts --include='*.rs' \
    | sed -E 's/.*gdt::([A-Z_]+_IST_INDEX).*/\1/' \
    | grep _IST_INDEX | sort -u || true)"
ist_init_missing=
for sym in ${ist_indices_used}; do
    case "${sym}" in
        NMI_IST_INDEX)        const='IST_NMI' ;;
        DF_IST_INDEX)         const='IST_DOUBLE_FAULT' ;;
        PF_IST_INDEX)         const='IST_PAGE_FAULT' ;;
        GP_IST_INDEX)         const='IST_GP' ;;
        MC_IST_INDEX)         const='IST_MACHINE_CHECK' ;;
        DEBUG_IST_INDEX)      const='IST_DEBUG' ;;
        *)                    const='' ;;
    esac
    if [ -z "${const}" ]; then
        ist_init_missing="${ist_init_missing}${sym} -> unknown\n"
        continue
    fi
    if ! grep -q "set_ist(${const}," src/arch/x86_64/gdt/percpu_struct.rs; then
        ist_init_missing="${ist_init_missing}${sym} (${const}) not initialised in PerCpuGdt::init\n"
    fi
done
if [ -n "${ist_init_missing}" ]; then
    fail_with "IDT IST indices without a backing TSS stack:"
    printf '%b' "${ist_init_missing}" >&2
else
    note ok "every IDT IST index is backed by a TSS stack in PerCpuGdt::init"
fi
unset ist_indices_used ist_init_missing sym const

# Kernel-half clone source. `create_address_space` must source the
# canonical kernel CR3 from `KERNEL_ASID`'s registered AddressSpace,
# never from `self.active_page_table` — once the scheduler runs, the
# active CR3 is whatever user CR3 is currently loaded.
clone_src='src/memory/paging/manager/address_space/clone.rs'
seed_src='src/memory/paging/manager/address_space/kernel_half.rs'
create_src='src/memory/paging/manager/address_space/create.rs'
if [ ! -f "${clone_src}" ]; then
    fail_with "missing ${clone_src}"
elif grep -qE '^[^/]*let[[:space:]]+[a-z_]+[[:space:]]*=[[:space:]]*self\.active_page_table' "${clone_src}"; then
    fail_with "${clone_src} clones kernel half from active_page_table — must use KERNEL_ASID"
elif ! grep -qE '\.get\(&KERNEL_ASID\)' "${clone_src}"; then
    fail_with "${clone_src} does not source kernel half from KERNEL_ASID"
elif [ ! -f "${seed_src}" ]; then
    fail_with "missing ${seed_src} (kernel-half PDPT pre-seed)"
elif ! grep -qE 'fn seed_kernel_half_pdpts' "${seed_src}"; then
    fail_with "${seed_src} must expose seed_kernel_half_pdpts"
elif [ ! -f "${create_src}" ]; then
    fail_with "missing ${create_src}"
elif ! grep -qE 'seed_kernel_half_pdpts' "${create_src}"; then
    fail_with "${create_src} must call seed_kernel_half_pdpts from create_kernel_address_space"
else
    note ok "kernel-half PDPTs are pre-seeded in KERNEL_ASID before any user clone"
fi
unset clone_src seed_src create_src

# ELF loader p_vaddr invariant. The user-mode ELF loader must honour
# the intra-page offset of `p_vaddr` so segment data lands at the
# right byte offset in the first page. populate_page takes a
# dst_off; load_segment computes intra = (p_vaddr & 0xFFF) and
# checks every length/address arithmetic step. A regression here
# silently shifts the user RIP bytes and the CPU executes garbage.
pop_src='src/elf/loader/core/load_segment/populate_page.rs'
seg_src='src/elf/loader/core/load_segment/run.rs'
if [ ! -f "${pop_src}" ] || [ ! -f "${seg_src}" ]; then
    fail_with "missing ELF loader sources at ${pop_src} / ${seg_src}"
elif ! grep -qE 'dst_off:[[:space:]]*usize' "${pop_src}"; then
    fail_with "${pop_src} must accept a dst_off parameter"
elif ! grep -qE '\(ph\.p_vaddr[[:space:]]*&[[:space:]]*0xFFF\)' "${seg_src}"; then
    fail_with "${seg_src} must compute the intra-page offset as (p_vaddr & 0xFFF)"
elif ! grep -qE 'p_filesz[[:space:]]*>[[:space:]]*ph\.p_memsz|ph\.p_filesz[[:space:]]*>[[:space:]]*ph\.p_memsz' "${seg_src}"; then
    fail_with "${seg_src} must reject p_filesz > p_memsz"
elif ! grep -qE 'checked_add' "${seg_src}"; then
    fail_with "${seg_src} must use checked_add for length and VA arithmetic"
else
    note ok "ELF loader honours p_vaddr intra-page offset with checked arithmetic"
fi
unset pop_src seg_src

# Usercopy hygiene — applies across the whole usercopy tree. The
# layer must not contain inline asm (CR3 reads route through
# arch::x86_64::paging::read_cr3); must not duplicate page-table
# constants; must not dereference user virtual addresses directly.
# Production transfers walk the caller's CR3 through the directmap
# and copy at DIRECTMAP_BASE + phys + offset.
ucopy_dir='src/usercopy'
if [ ! -d "${ucopy_dir}" ]; then
    fail_with "missing ${ucopy_dir}"
fi

ucopy_asm="$( { grep -RIn '\basm!\(' ${ucopy_dir} --include='*.rs' || true; } )"
if [ -n "${ucopy_asm}" ]; then
    fail_with "${ucopy_dir} contains inline asm — route through arch::x86_64"
    printf '%s\n' "${ucopy_asm}" >&2
else
    note ok "usercopy free of inline asm"
fi
unset ucopy_asm

ucopy_magic="$( { grep -RInE '0xFFFF_8000_0000_0000|0x000F_FFFF_FFFF_F000' ${ucopy_dir} --include='*.rs' \
    | grep -v '/tests/' \
    || true; } )"
if [ -n "${ucopy_magic}" ]; then
    fail_with "${ucopy_dir} contains magic page-table constants — use paging::constants"
    printf '%s\n' "${ucopy_magic}" >&2
else
    note ok "usercopy production code free of magic page-table constants"
fi
unset ucopy_magic

ucopy_raw_user_deref="$( { grep -RInE 'user_(ptr|src|dst|addr)[[:space:]]+as[[:space:]]+\*(const|mut)' ${ucopy_dir} --include='*.rs' || true; } )"
if [ -n "${ucopy_raw_user_deref}" ]; then
    fail_with "${ucopy_dir} dereferences a user pointer directly — copy through DIRECTMAP_BASE + phys"
    printf '%s\n' "${ucopy_raw_user_deref}" >&2
else
    note ok "usercopy never casts a user_ptr to *const/*mut"
fi
unset ucopy_raw_user_deref

ucopy_addr_deref="$( { grep -RInE 'ptr::read\([[:space:]]*addr[[:space:]]+as[[:space:]]+\*const|read_volatile\([[:space:]]*addr[[:space:]]+as[[:space:]]+\*const' ${ucopy_dir} --include='*.rs' || true; } )"
if [ -n "${ucopy_addr_deref}" ]; then
    fail_with "${ucopy_dir} reads a user address directly — translate via walk::translate first"
    printf '%s\n' "${ucopy_addr_deref}" >&2
else
    note ok "usercopy never reads a user address through a raw pointer"
fi
unset ucopy_addr_deref

if [ ! -f 'src/usercopy/walk/mod.rs' ]; then
    fail_with "missing src/usercopy/walk/mod.rs (page-table walker module)"
elif ! grep -qE 'use crate::arch::x86_64::paging::read_cr3' src/usercopy/walk/root.rs 2>/dev/null; then
    fail_with "src/usercopy/walk/root.rs must read CR3 through arch::x86_64::paging::read_cr3"
else
    note ok "usercopy::walk routes CR3 through arch helper"
fi

# Access-aware translation. The rest of the usercopy tree must use
# `translate_read` (mapped + USER) or `translate_write` (mapped +
# USER + WRITABLE), never a generic translator. The internal walker
# in `walk/levels.rs` is private; the public surface lives in
# `walk/access.rs` and `walk/mod.rs` re-exports only the access-
# aware helpers. The gate fails if a permission-less translator
# leaks back in or if `direct.rs` / `string.rs` stop using the
# access pair.
walk_mod='src/usercopy/walk/mod.rs'
access_src='src/usercopy/walk/access.rs'
direct_src='src/usercopy/direct.rs'
string_src='src/usercopy/string.rs'
validate_src='src/usercopy/validate.rs'
levels_src='src/usercopy/walk/levels.rs'
if [ ! -f "${access_src}" ]; then
    fail_with "missing ${access_src} (translate_read / translate_write)"
elif ! grep -qE 'fn translate_read|fn translate_write' "${access_src}"; then
    fail_with "${access_src} must define translate_read and translate_write"
elif grep -qE 'pub(\([^)]*\))?[[:space:]]+fn translate\b' "${levels_src}"; then
    fail_with "${levels_src} exposes a generic translate — must keep walking private"
elif grep -qE '^pub(\([^)]*\))?[[:space:]]+use[[:space:]].*::translate\b' "${walk_mod}"; then
    fail_with "${walk_mod} re-exports a generic translate — only translate_read/translate_write may be public"
elif ! grep -qE 'translate_read' "${direct_src}" || ! grep -qE 'translate_write' "${direct_src}"; then
    fail_with "${direct_src} must call translate_read for copy_from_user and translate_write for copy_to_user"
elif ! grep -qE 'translate_read' "${string_src}"; then
    fail_with "${string_src} must call translate_read"
elif grep -qE '\bfn[[:space:]]+walk_page_table\b|\bfn[[:space:]]+walk\b' "${validate_src}"; then
    fail_with "${validate_src} carries its own walker — delegate to walk::translate_read/_write"
else
    note ok "usercopy uses access-aware translate_read / translate_write everywhere"
fi
unset walk_mod access_src direct_src string_src validate_src levels_src

# A second usercopy implementation under syscall::validation must
# not exist. The single source of truth is crate::usercopy. Either
# the file is gone, or it contains no raw copy logic.
duplicate='src/syscall/validation/user_ptr.rs'
if [ -f "${duplicate}" ]; then
    if grep -qE 'ptr::copy_nonoverlapping' "${duplicate}"; then
        fail_with "${duplicate} carries a duplicate raw copy path — route through crate::usercopy or delete"
    else
        note ok "${duplicate} carries no raw user-copy path"
    fi
else
    note ok "no duplicate usercopy at ${duplicate}"
fi
unset duplicate
unset ucopy_dir

# Mk* syscall handlers must take user pointers as `u64` and route
# every byte transfer through `crate::usercopy`. A `*const u8` /
# `*mut u8` parameter on a sys_* signature is a footgun: it lets a
# future caller skip validation. Handlers also must not cast user
# values back to raw byte pointers — usercopy owns that conversion.
mk_dir='src/syscall/microkernel'
mk_raw_ptr_sigs="$( { grep -RnE 'pub[[:space:]]+fn[[:space:]]+sys_[a-z_]+\b[^;]*\*(const|mut)[[:space:]]+u8' ${mk_dir} --include='*.rs' || true; } )"
if [ -n "${mk_raw_ptr_sigs}" ]; then
    fail_with "${mk_dir} carries Mk* handler signatures that take *const u8 / *mut u8 — pass u64 and route through crate::usercopy"
    printf '%s\n' "${mk_raw_ptr_sigs}" >&2
else
    note ok "Mk* handlers receive user pointers as u64, not raw pointers"
fi
unset mk_raw_ptr_sigs

mk_user_casts="$( { grep -RnE 'as[[:space:]]+\*(const|mut)[[:space:]]+u8' ${mk_dir} --include='*.rs' || true; } )"
if [ -n "${mk_user_casts}" ]; then
    fail_with "${mk_dir} casts user values to raw byte pointers — usercopy owns that conversion"
    printf '%s\n' "${mk_user_casts}" >&2
else
    note ok "Mk* handlers free of raw user-pointer casts"
fi
unset mk_user_casts

mk_local_validate="$( { grep -RnE 'fn[[:space:]]+(walk_page_table|validate_user|in_user_range|read_cstr_from_user)' ${mk_dir} --include='*.rs' || true; } )"
if [ -n "${mk_local_validate}" ]; then
    fail_with "${mk_dir} reimplements user validation locally — call crate::usercopy"
    printf '%s\n' "${mk_local_validate}" >&2
else
    note ok "Mk* handlers do not reimplement usercopy validation"
fi
unset mk_local_validate
unset mk_dir

# Microkernel handler files must source negative errno values from
# `errnos.rs`, not redefine `const E_*: i64 = -<n>;` locally. A local
# duplicate drifts away from the central table the moment one site
# updates a value.
mk_dir='src/syscall/microkernel'
local_errno_consts="$( { grep -RnE '^[[:space:]]*const[[:space:]]+E[A-Z_]+:[[:space:]]*i64[[:space:]]*=[[:space:]]*-[0-9]+' \
    "${mk_dir}" --include='*.rs' \
    | grep -v '/errnos\.rs' \
    || true; } )"
if [ -n "${local_errno_consts}" ]; then
    fail_with "${mk_dir} carries local errno constants — use super::errnos::ERRNO_*"
    printf '%s\n' "${local_errno_consts}" >&2
else
    note ok "microkernel handlers route errnos through errnos.rs"
fi
unset local_errno_consts
unset mk_dir

# Production `dispatch.rs` is a numeric router only. Smoke-only
# `[SC ...]` tracing lives in `dispatch_trace.rs`, gated behind
# `nonos-user-entry-proof`. Any direct `serial::` call in dispatch.rs
# is production trace bleed and must move into the gated module.
dispatch_src='src/syscall/microkernel/dispatch.rs'
if [ ! -f "${dispatch_src}" ]; then
    fail_with "missing ${dispatch_src}"
elif grep -qE 'crate::sys::serial::|serial::print|serial::println' "${dispatch_src}"; then
    fail_with "${dispatch_src} carries unconditional serial output — move tracing into dispatch_trace.rs"
elif [ ! -f 'src/syscall/microkernel/dispatch_trace.rs' ]; then
    fail_with "missing src/syscall/microkernel/dispatch_trace.rs (gated tracing module)"
elif ! grep -qE 'feature = "nonos-user-entry-proof"' src/syscall/microkernel/mod.rs; then
    fail_with "src/syscall/microkernel/mod.rs must gate dispatch_trace on nonos-user-entry-proof"
else
    note ok "production dispatch carries no syscall trace; trace is feature-gated"
fi
unset dispatch_src

# `pcb_ops.rs::capability_token` runs on every syscall. It must not
# emit serial output and must not invoke `sign_capability_token` —
# the in-kernel derived token is never crossed across a trust
# boundary, so the signing cost is unmotivated and would saturate
# serial during ramfs / driver smoke runs.
pcb_ops_src='src/process/core/pcb_ops.rs'
if [ ! -f "${pcb_ops_src}" ]; then
    fail_with "missing ${pcb_ops_src}"
elif grep -qE 'crate::sys::serial::|serial::print|serial::println' "${pcb_ops_src}"; then
    fail_with "${pcb_ops_src} carries unconditional serial output — capability_token runs every syscall"
elif grep -qE 'sign_capability_token' "${pcb_ops_src}"; then
    fail_with "${pcb_ops_src} signs the in-kernel capability_token — the dispatch path must not pay Ed25519"
else
    note ok "capability_token() is silent and does not sign on the dispatch path"
fi
unset pcb_ops_src

# Capability ambient narrowing. `process::core::table::inherit` is
# the only producer of init's caps_bits and the inheritable bound
# every fork is intersected against. Production builds keep
# hardware authority (Driver/DeviceEnum/Mmio/Irq/Dma/Pio), Admin,
# Debug, and the graphics caps out of the ambient set. The
# const_assert in the file enforces this at compile time; this
# gate proves the const_assert and the forbidden mask still exist
# and that no forbidden bit was textually added to the ambient.
inherit_src='src/process/core/table/inherit.rs'
if [ ! -f "${inherit_src}" ]; then
    fail_with "missing ${inherit_src}"
elif ! grep -q '^const AMBIENT_CAPS:' "${inherit_src}"; then
    fail_with "${inherit_src} must declare AMBIENT_CAPS as the named ambient mask"
elif ! grep -q '^const FORBIDDEN_AMBIENT:' "${inherit_src}"; then
    fail_with "${inherit_src} must declare FORBIDDEN_AMBIENT covering Admin/Driver/DeviceEnum/Mmio/Irq/Dma/Pio/Debug/Graphics*"
elif ! grep -qE 'AMBIENT_CAPS[[:space:]]*&[[:space:]]*FORBIDDEN_AMBIENT[[:space:]]*==[[:space:]]*0' "${inherit_src}"; then
    fail_with "${inherit_src} must compile-time assert (AMBIENT_CAPS & FORBIDDEN_AMBIENT == 0)"
else
    ambient_block="$(awk '/^const AMBIENT_CAPS:/{g=1} g{print; if (/;/) exit}' "${inherit_src}")"
    forbidden_block="$(awk '/^const FORBIDDEN_AMBIENT:/{g=1} g{print; if (/;/) exit}' "${inherit_src}")"
    ambient_bad=""
    forbidden_missing=""
    for cap in Admin Driver DeviceEnum Mmio Irq Dma Pio Debug \
               GraphicsDisplayQuery GraphicsSurfaceCreate \
               GraphicsSurfaceMap GraphicsPresent; do
        if printf '%s' "${ambient_block}" | grep -qE "Capability::${cap}\.bit\(\)"; then
            ambient_bad="${ambient_bad} ${cap}"
        fi
        if ! printf '%s' "${forbidden_block}" | grep -qE "Capability::${cap}\.bit\(\)"; then
            forbidden_missing="${forbidden_missing} ${cap}"
        fi
    done
    if [ -n "${ambient_bad}" ]; then
        fail_with "${inherit_src} AMBIENT_CAPS includes forbidden bits:${ambient_bad}"
    elif [ -n "${forbidden_missing}" ]; then
        fail_with "${inherit_src} FORBIDDEN_AMBIENT missing entries:${forbidden_missing}"
    else
        note ok "init ambient set excludes Admin/Driver/DeviceEnum/Mmio/Irq/Dma/Pio/Debug/Graphics*"
    fi
    unset ambient_block forbidden_block ambient_bad forbidden_missing
fi
unset inherit_src

# Fork/clone child caps must route through `apply_inherit_bound`.
# A bare `parent.caps_bits.load(...)` flowing into the child PCB
# carries hardware authority across a fork.
clone_src='src/process/operations/clone.rs'
if [ ! -f "${clone_src}" ]; then
    fail_with "missing ${clone_src}"
elif ! grep -q 'apply_inherit_bound' "${clone_src}"; then
    fail_with "${clone_src} must call apply_inherit_bound on the parent's caps before cloning"
else
    bare_caps_load="$(grep -nE 'caps_bits\.load' "${clone_src}" | grep -v 'apply_inherit_bound' || true)"
    if [ -n "${bare_caps_load}" ]; then
        fail_with "${clone_src} reads parent.caps_bits without apply_inherit_bound"
        printf '%s\n' "${bare_caps_load}" >&2
    else
        note ok "fork/clone narrows parent caps through apply_inherit_bound"
    fi
    unset bare_caps_load
fi
unset clone_src

# Graphics surface honesty. The contract admits a fixed set of
# graphics syscall numbers; the dispatcher must route every one of
# them through `graphics_unavailable` (ENOTSUP) until a backend
# lands. A drift here would silently turn one number into ENOSYS
# and another into ENOTSUP.
graphics_cap_src='src/syscall/contract/cap_table/graphics.rs'
graphics_park_src='src/syscall/dispatch/router/graphics_unavailable.rs'
if [ ! -f "${graphics_cap_src}" ] || [ ! -f "${graphics_park_src}" ]; then
    fail_with "missing graphics contract or park module"
else
    contract_nrs="$(grep -oE 'SyscallNumber::Graphics[A-Za-z]+' "${graphics_cap_src}" | sort -u)"
    park_nrs="$(grep -oE 'SyscallNumber::Graphics[A-Za-z]+' "${graphics_park_src}" | sort -u)"
    missing=""
    for n in ${contract_nrs}; do
        if ! printf '%s\n' "${park_nrs}" | grep -qx "${n}"; then
            missing="${missing} ${n}"
        fi
    done
    if [ -n "${missing}" ]; then
        fail_with "${graphics_park_src} missing graphics numbers admitted by contract:${missing}"
    elif ! grep -qE 'graphics_unavailable::matches' src/syscall/dispatch/router/mod.rs; then
        fail_with "src/syscall/dispatch/router/mod.rs must route graphics through graphics_unavailable"
    else
        note ok "graphics syscalls route to ENOTSUP via graphics_unavailable"
    fi
    unset contract_nrs park_nrs missing
fi
unset graphics_cap_src graphics_park_src

# Graphics capabilities stay out of the ambient inheritance set.
# `FORBIDDEN_AMBIENT` already includes them; this gate fails loud
# if a graphics variant is silently dropped from the forbidden mask.
inherit_src='src/process/core/table/inherit.rs'
graphics_in_ambient="$(awk '/^const AMBIENT_CAPS:/{g=1} g{print; if (/;/) exit}' "${inherit_src}" \
    | grep -E 'Capability::Graphics(DisplayQuery|SurfaceCreate|SurfaceMap|Present)' || true)"
graphics_in_forbidden="$(awk '/^const FORBIDDEN_AMBIENT:/{g=1} g{print; if (/;/) exit}' "${inherit_src}" \
    | grep -E 'Capability::Graphics(DisplayQuery|SurfaceCreate|SurfaceMap|Present)' | wc -l \
    | tr -d ' ')"
if [ -n "${graphics_in_ambient}" ]; then
    fail_with "${inherit_src} AMBIENT_CAPS contains graphics caps"
elif [ "${graphics_in_forbidden}" -lt 4 ]; then
    fail_with "${inherit_src} FORBIDDEN_AMBIENT must list all four graphics caps"
else
    note ok "graphics caps stay out of AMBIENT_CAPS and stay in FORBIDDEN_AMBIENT"
fi
unset inherit_src graphics_in_ambient graphics_in_forbidden

# Production syscall router stays quiet. Any unknown-syscall
# diagnostic must live inside a cfg-gated submodule (currently
# `unknown_syscall_diag`); the router proper carries no
# unconditional serial output.
router_src='src/syscall/dispatch/router/mod.rs'
if [ ! -f "${router_src}" ]; then
    fail_with "missing ${router_src}"
elif ! grep -qE '^#\[cfg\(feature = "nonos-user-entry-proof"\)\]$' "${router_src}"; then
    if grep -qE 'crate::sys::serial::' "${router_src}"; then
        fail_with "${router_src} carries unconditional serial output — gate behind nonos-user-entry-proof"
    else
        note ok "syscall dispatch router carries no unconditional serial output"
    fi
else
    router_unconditional_serial="$(awk '
        /^mod unknown_syscall_diag / { in_diag=1 }
        in_diag && /^\}/ { in_diag=0; next }
        !in_diag && /crate::sys::serial::/ { print NR ": " $0 }
    ' "${router_src}")"
    if [ -n "${router_unconditional_serial}" ]; then
        fail_with "${router_src} carries unconditional serial output outside cfg-gated diag mod"
        printf '%s\n' "${router_unconditional_serial}" >&2
    else
        note ok "syscall dispatch router serial output stays inside cfg-gated diag mod"
    fi
    unset router_unconditional_serial
fi
unset router_src

# Production `debug.rs` carries one production print of the user
# buffer and nothing else. Diagnostics live in `debug_diag.rs`,
# compiled in only under `nonos-user-entry-proof`.
debug_src='src/syscall/microkernel/debug.rs'
if [ ! -f "${debug_src}" ]; then
    fail_with "missing ${debug_src}"
elif grep -qE '\[MkDebug-DIAG\]' "${debug_src}"; then
    fail_with "${debug_src} carries inline diagnostic output — move into debug_diag.rs"
elif [ ! -f 'src/syscall/microkernel/debug_diag.rs' ]; then
    fail_with "missing src/syscall/microkernel/debug_diag.rs (gated diagnostic module)"
else
    note ok "MkDebug diagnostics live in feature-gated debug_diag.rs"
fi
unset debug_src

# `microkernel/capability` is the MkCap* syscall surface and nothing
# else. The directory carries `mod.rs` and `handlers.rs` only — there
# is no parallel per-pid capability table, no `init.rs` bootstrap, and
# no legacy `grant_caps_internal` / `check_caps_internal`. Authority
# lives in `pcb.caps_bits` and is mutated through `process::caps`.
flat_cap='src/syscall/microkernel/capability.rs'
cap_dir='src/syscall/microkernel/capability'
if [ -e "${flat_cap}" ]; then
    fail_with "${flat_cap} reappeared — capability is a directory of {mod,handlers}.rs"
elif [ ! -f "${cap_dir}/mod.rs" ] || [ ! -f "${cap_dir}/handlers.rs" ]; then
    fail_with "${cap_dir} missing one of {mod,handlers}.rs"
elif [ -e "${cap_dir}/table.rs" ] || [ -e "${cap_dir}/init.rs" ]; then
    fail_with "${cap_dir} carries a parallel per-pid table — authority belongs in pcb.caps_bits via process::caps"
else
    note ok "microkernel capability is handler-only; no parallel per-pid table"
fi
unset flat_cap
unset cap_dir

# No call site may reach the deleted parallel-table API. `process::caps`
# is the only mutator/inspector of `pcb.caps_bits` outside `process`'s
# own internals; `Capability::resolve` plus `process::caps::has` is
# the single enforceable path.
parallel_cap_api="$( { grep -RnE '(check_caps_internal|grant_caps_internal|init_cap_for_init)\b' src --include='*.rs' || true; } )"
if [ -n "${parallel_cap_api}" ]; then
    fail_with "parallel capability API resurfaced — route through process::caps"
    printf '%s\n' "${parallel_cap_api}" >&2
else
    note ok "no parallel capability API; authorization routes through process::caps"
fi
unset parallel_cap_api

# `pcb.caps_bits` is mutated only inside `process` (the PCB itself,
# fork/clone/inherit, exec, isolation, capability drop) and by the
# unified `process::caps` API. A direct `caps_bits.store` /
# `caps_bits.fetch_or` outside that footprint is a parallel mutator
# and breaks the single-source-of-truth.
caps_bits_writers="$( { grep -RnE 'caps_bits\.(store|fetch_or|fetch_and|fetch_xor|swap|compare_exchange)\b' src --include='*.rs' \
    | grep -vE '^src/process/' \
    | grep -vE '^src/kernel_core/process_spawn/capsule_spawn/runner\.rs:' \
    || true; } )"
if [ -n "${caps_bits_writers}" ]; then
    fail_with "pcb.caps_bits is mutated outside process::caps and the spawn install path"
    printf '%s\n' "${caps_bits_writers}" >&2
else
    note ok "pcb.caps_bits writers stay inside process / spawn install path"
fi
unset caps_bits_writers

# PML4[0] cleared post-handoff. Cloning entry 0 would re-attach the
# bootloader low-half identity map to every fresh address space.
pml4_low_clone="$(grep -RIn 'page_table\[0\][[:space:]]*=' src/memory/paging --include='*.rs' \
    | grep -v 'page_table\[0\][[:space:]]*=[[:space:]]*0' \
    || true)"
if [ -n "${pml4_low_clone}" ]; then
    fail_with "page_table[0] is written to a non-zero value"
    printf '%s\n' "${pml4_low_clone}" >&2
else
    note ok "PML4[0] stays cleared in every address-space cloner"
fi
unset pml4_low_clone

# Pre-iretq proof must exist under the smoke/debug feature and must
# be the gatekeeper before iretq.
proof_orchestrator='src/arch/x86_64/diag/user_proof/mod.rs'
if [ ! -f "${proof_orchestrator}" ]; then
    fail_with "missing ${proof_orchestrator} (pre-iretq proof)"
elif ! grep -q 'feature = "nonos-user-entry-proof"' src/arch/x86_64/diag/mod.rs; then
    fail_with "diag/mod.rs does not gate user_proof on nonos-user-entry-proof"
elif ! grep -q 'assert_user_entry' src/process/userspace/asm.rs; then
    fail_with "return_to_usermode does not call assert_user_entry"
else
    note ok "pre-iretq proof present and wired into return_to_usermode"
fi
unset proof_orchestrator

# SYSCALL MSR init must be called from the active core boot path.
# arch::api::init exists and calls syscall::init, but it is the dead
# alternate path; the live entry is core_init::init_core_systems and
# the syscall::init call has to live there.
core_init='src/boot/main/core_init.rs'
if [ ! -f "${core_init}" ]; then
    fail_with "missing ${core_init}"
elif ! grep -q 'crate::arch::x86_64::syscall::init' "${core_init}"; then
    fail_with "${core_init} must call crate::arch::x86_64::syscall::init"
else
    note ok "core_init.rs calls arch::x86_64::syscall::init"
fi
unset core_init

# Per-CPU bootstrap on the active boot path. The SYSCALL trampoline
# reads `gs:0x20` (kernel_stack_top) and `gs:0x28` (user_stack_saved)
# right after `swapgs`. Without `crate::smp::init_bsp()` programming
# `MSR_GS_BASE` to PerCpuData, the very first user syscall lands on
# linear address 0x20 and triple-faults. The legacy `kernel_main`
# entry calls `init_bsp`; the production path is `microkernel_init`
# and that one must call it too.
mk_init='src/kernel_core/init/entry.rs'
if [ ! -f "${mk_init}" ]; then
    fail_with "missing ${mk_init}"
elif ! grep -q 'crate::smp::init_bsp' "${mk_init}"; then
    fail_with "${mk_init} must call crate::smp::init_bsp"
else
    note ok "microkernel_init calls smp::init_bsp"
fi
unset mk_init

# Per-CPU offset discipline. PerCpuData layout pins gs:0x20 to
# kernel_stack_top and gs:0x28 to user_stack_saved. gs:0x10 is
# `current_process` (an AtomicU64) and must never be used as the
# saved-user-stack slot. A regression to gs:0x10 read/write of an
# RSP-shaped value silently substitutes a process handle for a stack
# pointer; future #PF/#GP traps then land on garbage.
gs10_user_rsp="$( { grep -RIn 'gs:0x10' src --include='*.rs' \
    | grep -iE 'user.?rsp|user.?stack|saved.?rsp|saved.?stack' \
    || true; } )"
if [ -n "${gs10_user_rsp}" ]; then
    fail_with "gs:0x10 used as saved user stack — must be gs:0x28"
    printf '%s\n' "${gs10_user_rsp}" >&2
else
    note ok "no caller treats gs:0x10 as saved user stack"
fi
unset gs10_user_rsp

# SYSCALL trampoline ABI invariants. The NØNOS user ABI delivers
# arg4 in r10 (because rcx is clobbered by the SYSCALL instruction
# itself); the SysV C ABI requires arg7 (the seventh handler
# argument) to be stack-passed. The trampoline must move the saved
# r10 into the C arg5 register (r8) and push exactly one extra
# value before `call {handler}`.
trampoline='src/arch/x86_64/syscall/manager/entry.rs'
if [ ! -f "${trampoline}" ]; then
    fail_with "missing ${trampoline}"
else
    if ! grep -qE 'mov[[:space:]]+r8,[[:space:]]*\[rsp[[:space:]]*\+[[:space:]]*24\]' "${trampoline}"; then
        fail_with "${trampoline} does not move saved r10 into C arg5 (r8)"
    else
        note ok "syscall trampoline routes r10 into the fifth handler argument"
    fi
    seventh_push=$(awk '
        /push[[:space:]]+r1[01]/  { p = NR }
        /call[[:space:]]+\{handler\}/ {
            if (p && NR - p <= 3) {
                ok = 1
            }
            exit
        }
        END { print ok ? "ok" : "" }
    ' "${trampoline}")
    if [ -z "${seventh_push}" ]; then
        fail_with "${trampoline} does not stack-pass the seventh C argument before call {handler}"
    else
        note ok "syscall trampoline stack-passes the seventh handler argument"
    fi
    unset seventh_push
fi
unset trampoline

# NØNOS-native debug trace channel. Userland uses `mk_debug` to drive
# `MkDebug` (0x1050). Linux `write(fd, ...)` semantics must not exist
# anywhere in userland: no helper named `write`, no fd=1, no syscall
# number 1.
write_helper="$( { grep -RIn '\bnonos_libc::write\b' userland --include='*.rs' || true; } )"
if [ -n "${write_helper}" ]; then
    fail_with "userland uses nonos_libc::write — debug output must go through mk_debug"
    printf '%s\n' "${write_helper}" >&2
else
    note ok "userland free of nonos_libc::write"
fi
unset write_helper

write_const="$( { grep -RInE '^[[:space:]]*pub(\([^)]*\))?[[:space:]]+const[[:space:]]+N_WRITE:[[:space:]]+i64[[:space:]]+=[[:space:]]+1' userland --include='*.rs' || true; } )"
if [ -n "${write_const}" ]; then
    fail_with "active userland declares Linux write syscall (N_WRITE=1)"
    printf '%s\n' "${write_const}" >&2
else
    note ok "userland declares no N_WRITE=1 syscall constant"
fi
unset write_const

libc_debug_helper="$( { grep -nE '^pub use debug::mk_debug;' userland/libc/src/lib.rs || true; } )"
if [ -z "${libc_debug_helper}" ]; then
    fail_with "userland libc must export mk_debug (NØNOS-native debug trace)"
else
    note ok "userland libc exports mk_debug"
fi
unset libc_debug_helper

libc_mk_debug="$(grep -E '^pub(\([^)]*\))? const N_MK_DEBUG: i64 = ' userland/libc/src/syscall/numbers/mod.rs | sed 's/.*= //; s/;.*//')"
kern_mk_debug="$(grep -E '^pub const SYS_MK_DEBUG: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"
if [ "${libc_mk_debug}" != "${kern_mk_debug}" ] || [ -z "${libc_mk_debug}" ]; then
    fail_with "ABI drift: libc N_MK_DEBUG=${libc_mk_debug} vs kernel SYS_MK_DEBUG=${kern_mk_debug}"
else
    note ok "libc N_MK_DEBUG matches kernel SYS_MK_DEBUG"
fi
unset libc_mk_debug kern_mk_debug

# The active SyscallNumber enum is NØNOS-owned. No Linux variant
# names may appear; the entire enum is a closed set of NØNOS
# numbers (Crypto*, Mk*, Graphics*, IoPort*/MmioMap, Debug*, Admin*).
defs_src='src/syscall/numbers/defs.rs'
linux_variants_in_enum="$(grep -nE '^[[:space:]]+(Read|Write|Open|Close|Stat|Fstat|Lstat|Poll|Lseek|Mmap|Mprotect|Munmap|Brk|RtSig[A-Za-z]+|Ioctl|Pread64|Pwrite64|Readv|Writev|Access|Pipe|Pipe2|Select|Pselect6|Fork|Vfork|Clone|Execve|Execveat|Exit|ExitGroup|Wait4|Waitid|Kill|Tkill|Tgkill|Uname|Sigaltstack|Fcntl|Flock|Fsync|Fdatasync|Truncate|Ftruncate|Getdents|Getdents64|Getcwd|Chdir|Fchdir|Rename|Renameat|Renameat2|Mkdir|Mkdirat|Rmdir|Creat|Link|Linkat|Unlink|Unlinkat|Symlink|Symlinkat|Readlink|Readlinkat|Chmod|Fchmod|Fchmodat|Chown|Fchown|Lchown|Fchownat|Mknod|Mknodat|Umask|Statfs|Fstatfs|Statx|Newfstatat|Faccessat|Sysfs|Openat|Sendfile|Splice|Tee|Vmsplice|CopyFileRange|Fallocate|Sync|Syncfs|SyncFileRange|Utime|Utimes|Utimensat|Futimesat|Setxattr|Getxattr|Listxattr|Removexattr|Lsetxattr|Lgetxattr|Llistxattr|Lremovexattr|Fsetxattr|Fgetxattr|Flistxattr|Fremovexattr|Mremap|Madvise|Mincore|Mlock|Munlock|Mlockall|Munlockall|Mlock2|Mbind|GetMempolicy|SetMempolicy|MovePages|MigratePages|MemfdCreate|RemapFilePages|Shmget|Shmat|Shmdt|Shmctl|Semget|Semop|Semctl|Semtimedop|Msgget|Msgsnd|Msgrcv|Msgctl|MqOpen|MqUnlink|MqNotify|MqGetsetattr|MqTimedsend|MqTimedreceive|Socket|Socketpair|Bind|Listen|Accept|Accept4|Connect|Sendto|Recvfrom|Sendmsg|Recvmsg|Sendmmsg|Recvmmsg|Shutdown|Setsockopt|Getsockopt|Getsockname|Getpeername|EpollCreate|EpollCreate1|EpollCtl|EpollCtlOld|EpollWait|EpollWaitOld|EpollPwait|Eventfd|Eventfd2|InotifyInit|InotifyInit1|InotifyAddWatch|InotifyRmWatch|FanotifyInit|FanotifyMark|Signalfd|Signalfd4|TimerfdCreate|TimerfdSettime|TimerfdGettime|TimerCreate|TimerSettime|TimerGettime|TimerGetoverrun|TimerDelete|ClockGettime|ClockSettime|ClockGetres|ClockNanosleep|ClockAdjtime|Adjtimex|Settimeofday|Gettimeofday|Time|Times|Alarm|Getitimer|Setitimer|Nanosleep|Pause|Yield|SchedSet[A-Za-z]+|SchedGet[A-Za-z]+|SchedRrGetInterval|Sched[A-Za-z]+attr|Futex|Getuid|Getgid|Geteuid|Getegid|Setuid|Setgid|Setreuid|Setregid|Setresuid|Getresuid|Setresgid|Getresgid|Getgroups|Setgroups|Setfsuid|Setfsgid|Setpgid|Getppid|Getpgrp|Getpgid|Setsid|Getsid|Getpid|Gettid|Capget|Capset|Getrlimit|Setrlimit|Prlimit64|Getrusage|Sysinfo|Ptrace|Syslog|Personality|Reboot|Sethostname|Setdomainname|Iopl|Ioperm|InitModule|DeleteModule|FinitModule|CreateModule|QueryModule|GetKernelSyms|Quotactl|KexecLoad|KexecFileLoad|Acct|Swapon|Swapoff|Bpf|Chroot|Mount|Umount2|PivotRoot|Sysctl|LookupDcookie|Nfsservctl|Vhangup|Putpmsg|Getpmsg|Tuxcall|Vserver|Security|Ustat|Uselib|AfsSyscall|Kcmp|IoSetup|IoDestroy|IoSubmit|IoCancel|IoGetevents|IoPgetevents|ProcessVmReadv|ProcessVmWritev|RestartSyscall|Dup|Dup2|Dup3|Sendmsg|Recvmsg|Brk|Mremap|Madvise|Mprotect|Mincore|Mlock|Munlock|Mlockall|Munlockall|Mlock2|Membarrier|PerfEventOpen|Seccomp|Getrandom|Userfaultfd|Preadv|Pwritev|Preadv2|Pwritev2|PkeyMprotect|PkeyAlloc|PkeyFree|Rseq|RtTgsigqueueinfo|GetThreadArea|SetThreadArea|SetTidAddress|SetRobustList|GetRobustList|Sigaltstack|RtSigqueueinfo|NameToHandleAt|OpenByHandleAt|Setns|Getcpu|ModifyLdt|ArchPrctl|Prctl|AddKey|RequestKey|Keyctl|IoprioSet|IoprioGet|Tee|Splice|Vmsplice)[[:space:]]*=' "${defs_src}" || true)"
if [ -n "${linux_variants_in_enum}" ]; then
    fail_with "${defs_src} contains Linux-shape variant names; the active enum must be NØNOS-only"
    printf '%s\n' "${linux_variants_in_enum}" >&2
else
    note ok "active SyscallNumber enum carries no Linux-shape variants"
fi
unset linux_variants_in_enum defs_src

# No `int80` anywhere in active surfaces.
int80_hits="$( { grep -RInE '\bint80\b|\b0x80\s*;.*syscall|int[[:space:]]*\$0x80' src userland 2>/dev/null \
    | grep -vE '^docs/|/tests?/|/legacy/|/test_vectors/' || true; } )"
if [ -n "${int80_hits}" ]; then
    fail_with "active surfaces reference int80"
    printf '%s\n' "${int80_hits}" >&2
else
    note ok "no int80 references in active surfaces"
fi
unset int80_hits

# No Linux-shape syscall ABI names in active userland libc public
# exports. Lowercase POSIX shape (`mmap`, `_exit`, `read`, `write`,
# `open`, `close`, `fork`, `execve`) must not be in `lib.rs::pub use`.
libc_lib='userland/libc/src/lib.rs'
linux_libc_exports="$(grep -E '^pub use ' "${libc_lib}" | grep -oE '\b(mmap|munmap|_exit|exit|exit_group|read|write|open|openat|close|fork|vfork|execve|brk|mprotect|getpid|sigaction|rt_sigaction)\b' || true)"
if [ -n "${linux_libc_exports}" ]; then
    fail_with "${libc_lib} exports Linux-shape ABI names"
    printf '%s\n' "${linux_libc_exports}" >&2
else
    note ok "userland libc exports only Mk*/NØNOS surface"
fi
unset linux_libc_exports libc_lib

# No "compatibility" / "compat" / "Linux"-as-ABI language in active
# Cargo metadata (kernel + userland). Test/legacy fixtures are
# excluded.
linux_cargo_lang="$( { grep -RInE 'linux[ -]compat|posix[ -]compat|abi[ -]compat|linux-shape|"compatibility"|int80' Cargo.toml userland/*/Cargo.toml 2>/dev/null \
    | grep -vE '/legacy/|/test|^docs/' || true; } )"
if [ -n "${linux_cargo_lang}" ]; then
    fail_with "Cargo metadata advertises Linux/compat shape"
    printf '%s\n' "${linux_cargo_lang}" >&2
else
    note ok "Cargo metadata carries no Linux/compat ABI language"
fi
unset linux_cargo_lang

# Cap-table chain admits NØNOS-only families. file_fs/ipc/io_event/
# memory/network/process_sched/signal/time used to host Linux-only
# arms; they are deleted now and must not reappear.
cap_dir='src/syscall/contract/cap_table'
forbidden_cap_files=""
for f in file_fs.rs io_event.rs ipc.rs memory.rs network.rs process_sched.rs signal.rs time.rs; do
    if [ -e "${cap_dir}/${f}" ]; then
        forbidden_cap_files="${forbidden_cap_files} ${f}"
    fi
done
if [ -n "${forbidden_cap_files}" ]; then
    fail_with "${cap_dir} carries deleted Linux-only family files:${forbidden_cap_files}"
elif ! grep -qE 'mk::check\(' "${cap_dir}/mod.rs"; then
    fail_with "${cap_dir}/mod.rs is missing the mk family"
else
    note ok "cap-table chain admits only NØNOS families"
fi
unset cap_dir forbidden_cap_files

# Phase B: active CPU ABI uses tag4-packed ASCII identifiers.
# `SyscallNumber` discriminants, `microkernel::SYS_*` constants,
# and userland `N_*` constants must all be `tag4(b"....")`. No
# raw old-format Mk numeric IDs may remain as syscall constants.
defs_src='src/syscall/numbers/defs.rs'
sys_src='src/syscall/microkernel/numbers.rs'
libc_numbers='userland/libc/src/syscall/numbers/mod.rs'

defs_non_tag="$(awk '/^pub enum SyscallNumber/{f=1; next} f && /^}/{exit} f && /=/' "${defs_src}" \
    | grep -vE '=[[:space:]]*tag4\(b"[A-Z0-9]{4}"\)' || true)"
if [ -n "${defs_non_tag}" ]; then
    fail_with "${defs_src} has SyscallNumber discriminants that are not tag4(b\"....\")"
    printf '%s\n' "${defs_non_tag}" >&2
else
    note ok "every SyscallNumber discriminant is tag4(b\"....\")"
fi
unset defs_non_tag

sys_non_tag="$(grep -E '^pub const SYS_' "${sys_src}" | grep -vE '=[[:space:]]*tag4\(b"[A-Z0-9]{4}"\);' || true)"
if [ -n "${sys_non_tag}" ]; then
    fail_with "${sys_src} has SYS_* constants that are not tag4(b\"....\")"
    printf '%s\n' "${sys_non_tag}" >&2
else
    note ok "every microkernel SYS_* constant is tag4(b\"....\")"
fi
unset sys_non_tag

libc_non_tag="$(grep -E '^pub\(crate\) const N_' "${libc_numbers}" | grep -vE '=[[:space:]]*tag4\(b"[A-Z0-9]{4}"\);' || true)"
if [ -n "${libc_non_tag}" ]; then
    fail_with "${libc_numbers} has N_* constants that are not tag4(b\"....\")"
    printf '%s\n' "${libc_non_tag}" >&2
else
    note ok "every userland libc N_* constant is tag4(b\"....\")"
fi
unset libc_non_tag

# No old-format numeric syscall IDs may remain as syscall
# constants in the active syscall surfaces. Old Mk range was
# 0x1000..0x1050; old parked range was 900..1309.
old_mk_lits="$(grep -nE '=[[:space:]]*0x10[0-5][0-9a-fA-F]\b' "${defs_src}" "${sys_src}" "${libc_numbers}" || true)"
old_parked_lits="$(grep -nE '=[[:space:]]*(9[0-9]{2}|10[0-9]{2}|11[0-9]{2}|12[0-9]{2}|13[0-9]{2})[[:space:]]*;' "${defs_src}" "${sys_src}" "${libc_numbers}" || true)"
if [ -n "${old_mk_lits}" ]; then
    fail_with "old Mk numeric IDs (0x10xx) remain in syscall constants"
    printf '%s\n' "${old_mk_lits}" >&2
elif [ -n "${old_parked_lits}" ]; then
    fail_with "old parked numeric IDs (900..1309) remain in syscall constants"
    printf '%s\n' "${old_parked_lits}" >&2
else
    note ok "no old-format syscall numeric IDs remain in active surfaces"
fi
unset old_mk_lits old_parked_lits defs_src sys_src libc_numbers

# ABI registry coverage. `src/syscall/abi/registry.rs` is the
# single source of truth; every SyscallNumber variant must appear
# exactly once with a unique 4-byte ASCII tag and matching domain
# / status. `convert.rs` must route through `abi::lookup_id`
# and not carry a parallel match table.
abi_registry='src/syscall/abi/registry.rs'
syscall_defs='src/syscall/numbers/defs.rs'
convert_src='src/syscall/numbers/convert.rs'
graphics_park='src/syscall/dispatch/router/graphics_unavailable.rs'
router_src='src/syscall/dispatch/router/mod.rs'

if [ ! -f "${abi_registry}" ]; then
    fail_with "missing ${abi_registry}"
elif ! grep -qE '^[[:space:]]+abi::lookup_id\(' "${convert_src}"; then
    fail_with "${convert_src} must look up syscall ids via abi::lookup_id"
elif grep -qE '^[[:space:]]+[0-9]+[[:space:]]*=>[[:space:]]*Some\(Self::' "${convert_src}"; then
    fail_with "${convert_src} carries a parallel numeric match table; route through the registry"
else
    enum_variants="$(awk '/^pub enum SyscallNumber/{f=1; next} f && /^}/{exit} f && /^[[:space:]]+[A-Z][A-Za-z0-9]+[[:space:]]*=/{print $1}' "${syscall_defs}" | tr -d ',' | sort -u)"
    registry_variants="$(grep -oE 'variant: SyscallNumber::[A-Za-z0-9]+' "${abi_registry}" | sed 's/.*:://' | sort)"
    registry_unique="$(printf '%s\n' "${registry_variants}" | sort -u)"
    if [ "${registry_variants}" != "${registry_unique}" ]; then
        fail_with "${abi_registry} contains duplicate variants"
    elif [ "${enum_variants}" != "${registry_unique}" ]; then
        fail_with "${abi_registry} variant set does not match SyscallNumber enum"
        diff <(printf '%s\n' "${enum_variants}") <(printf '%s\n' "${registry_unique}") >&2 || true
    else
        tag_count="$( { grep -cE 'id: tag4\(b"[A-Z0-9]{4}"\)' "${abi_registry}" || true; } )"
        tag_unique="$( { grep -oE 'tag4\(b"[A-Z0-9]{4}"\)' "${abi_registry}" || true; } | sort -u | wc -l | tr -d ' ')"
        bad_tags="$( { grep -oE 'tag4\(b"[^"]*"\)' "${abi_registry}" || true; } | grep -vE 'tag4\(b"[A-Z0-9]{4}"\)' || true)"
        entry_count="$( { grep -cE '^[[:space:]]+AbiEntry \{' "${abi_registry}" || true; } )"
        if [ -n "${bad_tags}" ]; then
            fail_with "${abi_registry} contains tags outside [A-Z0-9]{4}"
            printf '%s\n' "${bad_tags}" >&2
        elif [ "${tag_count}" != "${tag_unique}" ] || [ "${tag_count}" != "${entry_count}" ]; then
            fail_with "${abi_registry} tag count mismatch (entries=${entry_count} tags=${tag_count} unique=${tag_unique})"
        else
            note ok "abi registry covers every SyscallNumber variant with a unique ASCII tag"
        fi
        unset tag_count tag_unique bad_tags entry_count
    fi
    unset enum_variants registry_variants registry_unique
fi

# Routed entries: every registry entry whose status is `Routed`
# must appear by name in the dispatcher (router/mod.rs sees Mk*
# and Crypto* directly). Unavailable entries do not need router
# coverage; Graphics* additionally must be in graphics_unavailable.
if [ -f "${abi_registry}" ] && [ -f "${router_src}" ] && [ -f "${graphics_park}" ]; then
    routed_variants="$(awk '
        /^[[:space:]]+AbiEntry \{/{in_e=1; var=""; status=""}
        in_e && /variant: SyscallNumber::/{sub(/.*::/, ""); sub(/,.*/, ""); var=$0}
        in_e && /status: AbiStatus::/{sub(/.*::/, ""); sub(/,.*/, ""); status=$0}
        in_e && /^[[:space:]]+\},/{if (status == "Routed") print var; in_e=0}
    ' "${abi_registry}")"
    routed_missing=""
    for v in ${routed_variants}; do
        if ! grep -qE "SyscallNumber::${v}\b" "${router_src}"; then
            routed_missing="${routed_missing} ${v}"
        fi
    done
    if [ -n "${routed_missing}" ]; then
        fail_with "ABI registry: routed variants not found in router:${routed_missing}"
    else
        note ok "every Routed registry entry is named in the dispatcher"
    fi
    unset routed_missing routed_variants

    graphics_variants="$(awk '
        /^[[:space:]]+AbiEntry \{/{in_e=1; var=""; dom=""}
        in_e && /variant: SyscallNumber::/{sub(/.*::/, ""); sub(/,.*/, ""); var=$0}
        in_e && /domain: AbiDomain::/{sub(/.*::/, ""); sub(/,.*/, ""); dom=$0}
        in_e && /^[[:space:]]+\},/{if (dom == "Graphics") print var; in_e=0}
    ' "${abi_registry}")"
    graphics_status_drift="$(awk '
        /^[[:space:]]+AbiEntry \{/{in_e=1; var=""; dom=""; status=""}
        in_e && /variant: SyscallNumber::/{sub(/.*::/, ""); sub(/,.*/, ""); var=$0}
        in_e && /domain: AbiDomain::/{sub(/.*::/, ""); sub(/,.*/, ""); dom=$0}
        in_e && /status: AbiStatus::/{sub(/.*::/, ""); sub(/,.*/, ""); status=$0}
        in_e && /^[[:space:]]+\},/{if (dom == "Graphics" && status != "Unavailable") print var; in_e=0}
    ' "${abi_registry}")"
    graphics_bad=""
    for v in ${graphics_variants}; do
        if ! grep -qE "SyscallNumber::${v}\b" "${graphics_park}"; then
            graphics_bad="${graphics_bad} ${v}"
        fi
    done
    if [ -n "${graphics_status_drift}" ]; then
        fail_with "ABI registry: Graphics entries not Unavailable: ${graphics_status_drift}"
    elif [ -n "${graphics_bad}" ]; then
        fail_with "ABI registry: Graphics variants missing from graphics_unavailable:${graphics_bad}"
    else
        note ok "every Graphics registry entry is Unavailable and listed in graphics_unavailable"
    fi
    unset graphics_bad graphics_status_drift graphics_variants
fi
unset abi_registry syscall_defs convert_src graphics_park router_src

# Smoke-critical bring-up markers. The boot harnesses grep for these
# exact strings; if a refactor strips them the smoke fails silently
# even though the driver works. Source-of-truth is the harness file
# under tests/boot/, but the producers must exist in the capsule
# tree.
xhci_markers="reset ok|cnr cleared|scratchpads ok|dcbaa ok|cmd ring ok|evt ring ok|running|noop ok|endpoint driver.xhci0 ready"
xhci_marker_misses=0
for m in "reset ok" "cnr cleared" "scratchpads ok" "dcbaa ok" "cmd ring ok" "evt ring ok" "running" "noop ok" "endpoint driver.xhci0 ready"; do
    if ! grep -RIqF "${m}" userland/capsule_driver_xhci/src 2>/dev/null; then
        echo "::error::missing xhci bring-up marker producer: \"${m}\"" >&2
        xhci_marker_misses=$((xhci_marker_misses + 1))
    fi
done
if [ "${xhci_marker_misses}" -gt 0 ]; then
    fail_with "${xhci_marker_misses} xhci smoke marker producers missing"
else
    note ok "xhci smoke marker producers present in capsule_driver_xhci"
fi
unset xhci_markers xhci_marker_misses m

if ! grep -RIqF "endpoint driver.ps2_kbd0 ready" userland/capsule_driver_ps2_input/src 2>/dev/null; then
    fail_with "ps2 endpoint-ready marker producer missing"
else
    note ok "ps2 endpoint-ready marker producer present in capsule_driver_ps2_input"
fi

# Cargo metadata truth gates. The kernel and capsule manifests must
# describe the real Mk* ABI: no int-vector gateway, no Linux-shape
# syscall names, no POSIX fd rhetoric, no compatibility-shim or
# stub language. Header comments and `description =` strings are
# user-visible ABI claims and live under the same gate.
cargo_files="$(find . -maxdepth 5 -name 'Cargo.toml' \
    -not -path './target/*' -not -path './.claude/*' \
    -not -path './nonos-sign/target/*' -not -path './nonos-mk/target/*' -not -path './userland/*/target/*' \
    -not -path './nonos-bootloader/target/*' -not -path './docs/legacy/*' \
    2>/dev/null)"

cargo_int80="$( { grep -nE '\bint80\b' ${cargo_files} 2>/dev/null || true; } )"
if [ -n "${cargo_int80}" ]; then
    fail_with "Cargo metadata advertises int80 — NØNOS uses x86_64 syscall/sysret"
    printf '%s\n' "${cargo_int80}" >&2
else
    note ok "no Cargo metadata declares int80 gateway"
fi
unset cargo_int80

cargo_linux_names="$( { grep -nE '"(LOG_WRITE|EXIT_LINUX|MMAP_LINUX|RT_SIGRETURN)"|"(READ|WRITE|OPEN|CLOSE)"[[:space:]]*[,\]]' ${cargo_files} 2>/dev/null || true; } )"
if [ -n "${cargo_linux_names}" ]; then
    fail_with "Cargo metadata declares Linux-shape syscall names (READ/WRITE/OPEN/CLOSE/LOG_WRITE)"
    printf '%s\n' "${cargo_linux_names}" >&2
else
    note ok "no Cargo metadata declares Linux-shape syscall names"
fi
unset cargo_linux_names

cargo_low_numbers="$( { awk '
    /^[[:space:]]*\[package\.metadata\.nonos\.syscall\]/ { in_block = 1; next }
    /^[[:space:]]*\[/ { in_block = 0 }
    in_block && /numbers[[:space:]]*=/ { capture = 1 }
    capture {
        line = $0
        gsub(/[^0-9xXa-fA-F,]/, " ", line)
        n = split(line, a, /[[:space:]]+/)
        for (i = 1; i <= n; i++) {
            v = a[i]
            if (v == "" ) continue
            if (v ~ /^0[xX]/) {
                # hex: keep as-is
                if (v ~ /^0[xX]0*[0-9]$/) print FILENAME ":" NR ": " v
            } else if (v ~ /^[0-9]+$/) {
                if (v + 0 < 16) print FILENAME ":" NR ": " v
            }
        }
        if ($0 ~ /\]/) capture = 0
    }
' ${cargo_files} 2>/dev/null || true; } )"
if [ -n "${cargo_low_numbers}" ]; then
    fail_with "Cargo metadata advertises Linux-shape syscall numbers (0..15) under nonos.syscall"
    printf '%s\n' "${cargo_low_numbers}" >&2
else
    note ok "no Cargo metadata declares Linux-shape syscall numbers"
fi
unset cargo_low_numbers

cargo_forbidden_lang="$( { grep -nEi '\b(linux-shape|posix compatibility|compatibility shim|stub until|write\(1\b)' ${cargo_files} 2>/dev/null || true; } )"
if [ -n "${cargo_forbidden_lang}" ]; then
    fail_with "Cargo metadata uses forbidden ABI language (linux-shape / posix compatibility / shim / stub / write(1)"
    printf '%s\n' "${cargo_forbidden_lang}" >&2
else
    note ok "no Cargo metadata uses forbidden ABI compatibility language"
fi
unset cargo_forbidden_lang

cargo_old_proof_io="$( { grep -nE 'calls write then|calls write\(' userland/capsule_proof_io/Cargo.toml 2>/dev/null || true; } )"
if [ -n "${cargo_old_proof_io}" ]; then
    fail_with "capsule_proof_io Cargo.toml still describes a Linux write call"
    printf '%s\n' "${cargo_old_proof_io}" >&2
else
    note ok "capsule_proof_io Cargo.toml describes the MkDebug round trip"
fi
unset cargo_old_proof_io

# Honesty gate: a manifest may not advertise something as
# "production-ready" / "production proven" without a matching smoke
# feature in the same file. The smoke feature is the only artefact
# that justifies the claim.
cargo_prod_claims="$( { for f in ${cargo_files}; do
    if grep -qiE 'production[- ](ready|proven)' "$f" 2>/dev/null; then
        if ! grep -qE 'smoketest' "$f" 2>/dev/null; then
            grep -niE 'production[- ](ready|proven)' "$f"
        fi
    fi
done } )"
if [ -n "${cargo_prod_claims}" ]; then
    fail_with "Cargo metadata claims production-ready without a matching smoketest feature"
    printf '%s\n' "${cargo_prod_claims}" >&2
else
    note ok "no Cargo metadata claims production-ready without a smoketest gate"
fi
unset cargo_prod_claims cargo_files

# Slice B post-cleanup gates: hard-fail once the legacy 3-entry
# sys::gdt tree is removed. These gates exist now so that the
# tree cannot reappear after Slice B; they no-op while the tree
# still exists (Slice A keeps it on disk so the dead 3-entry
# subsystem can be inspected).
if [ -d src/sys/gdt ]; then
    note skip "src/sys/gdt still present (Slice B not yet landed)"
else
    note ok "src/sys/gdt removed"
fi

if grep -nE '^\s*pub mod gdt;' src/sys/mod.rs >/dev/null 2>&1; then
    if [ -d src/sys/gdt ]; then
        note skip "sys/mod.rs still declares pub mod gdt (Slice B pending)"
    else
        fail_with "sys/mod.rs declares pub mod gdt but the directory is gone"
        grep -nE '^\s*pub mod gdt;' src/sys/mod.rs >&2
    fi
else
    note ok "sys/mod.rs no longer declares pub mod gdt"
fi

if grep -nE '^\s*pub mod gdt_tests;' src/sys/tests/mod.rs >/dev/null 2>&1; then
    if [ -f src/sys/tests/gdt_tests.rs ]; then
        note skip "sys/tests/gdt_tests.rs still present (Slice B pending)"
    else
        fail_with "sys/tests/mod.rs declares pub mod gdt_tests but the file is gone"
    fi
else
    note ok "sys/tests/mod.rs no longer declares pub mod gdt_tests"
fi

# Capsule IPC port uniqueness. SERVICE_PORT and REPLY_PORT in each
# capsule's spawn.rs share one numeric namespace; a collision makes
# the second spawn fail with SpawnError::EndpointCollision.
if nonos-ci/check-capsule-ports.sh src/hardware src/fs src/security src/userspace >/dev/null; then
    note ok "capsule SERVICE_PORT/REPLY_PORT pairs unique"
else
    fail_with "capsule IPC port collision"
    nonos-ci/check-capsule-ports.sh src/hardware src/fs src/security src/userspace >&2 || true
fi

# init_handoff must run validate_security on every BootHandoffV1
# before the kernel consumes any bootloader-provided field.
handoff_init=src/boot/handoff/api/init.rs
handoff_orch=src/boot/handoff/api/security/orchestrator.rs
if [ ! -f "${handoff_init}" ]; then
    fail_with "missing ${handoff_init}"
elif [ ! -f "${handoff_orch}" ]; then
    fail_with "missing ${handoff_orch}"
elif ! grep -q 'fn validate_security' "${handoff_orch}"; then
    fail_with "${handoff_orch} must define validate_security"
elif ! grep -q 'validate_security(handoff)' "${handoff_init}"; then
    fail_with "${handoff_init} must call validate_security(handoff)"
else
    note ok "init_handoff calls validate_security"
fi
unset handoff_init handoff_orch

# NØNOS trust-anchor module ships the policy decoder and the
# baked-policy slot the kernel embeds at build time. The slot can be
# `Option<&[u8]> = None` during Lane B integration; once Lane B emits
# .keys/nonos_trust_anchor.policy.bin, baked.rs flips to a non-Option
# include_bytes! and a separate gate enforces "no None" in production.
ta_dir=src/security/nonos_trust_anchor
if [ ! -d "${ta_dir}" ]; then
    fail_with "missing ${ta_dir}"
elif [ ! -f "${ta_dir}/baked.rs" ]; then
    fail_with "${ta_dir}/baked.rs missing"
elif ! grep -q 'BAKED_TRUST_ANCHOR_POLICY' "${ta_dir}/baked.rs"; then
    fail_with "${ta_dir}/baked.rs must define BAKED_TRUST_ANCHOR_POLICY"
elif ! grep -q 'NonosTrustAnchorPolicy' "${ta_dir}/schema.rs"; then
    fail_with "${ta_dir}/schema.rs must define NonosTrustAnchorPolicy"
else
    note ok "NØNOS trust-anchor module present"
fi
unset ta_dir

# NØNOS-ID certificate module: schema/, decode/, verify/, derive.rs,
# policy.rs. The binary decoder is the authority — there is no JSON
# schema mirror anymore (the wire format is binary).
idc_dir=src/security/nonos_id_cert
if [ ! -d "${idc_dir}" ]; then
    fail_with "missing ${idc_dir}"
elif [ ! -d "${idc_dir}/schema" ] || [ ! -f "${idc_dir}/schema/cert.rs" ]; then
    fail_with "${idc_dir}/schema/cert.rs missing"
elif [ ! -d "${idc_dir}/decode" ] || [ ! -f "${idc_dir}/decode/mod.rs" ]; then
    fail_with "${idc_dir}/decode/mod.rs missing"
elif [ ! -d "${idc_dir}/verify" ] || [ ! -f "${idc_dir}/verify/dispatch.rs" ]; then
    fail_with "${idc_dir}/verify/dispatch.rs missing"
elif ! grep -q 'NonosIdCertificate' "${idc_dir}/schema/cert.rs"; then
    fail_with "${idc_dir}/schema/cert.rs must define NonosIdCertificate"
elif ! grep -q 'derive_nonos_id' "${idc_dir}/derive.rs"; then
    fail_with "${idc_dir}/derive.rs must define derive_nonos_id"
elif ! grep -q 'NONOS_PRODUCTION_POLICY' "${idc_dir}/policy.rs"; then
    fail_with "${idc_dir}/policy.rs must define NONOS_PRODUCTION_POLICY"
else
    note ok "NØNOS-ID cert module present (schema, decode, verify, derive, policy)"
fi
unset idc_dir

# Capsule manifest v3: payload_hash binds the ELF, target_triple
# binds the runtime ABI, endpoint kind+port+name binds IPC. Modular
# layout: schema/, decode/, verify/. entry_hash remains forbidden
# (no entry-window verifier in the kernel).
mf_dir=src/security/capsule_manifest
if [ ! -d "${mf_dir}" ]; then
    fail_with "missing ${mf_dir}"
elif [ ! -f "${mf_dir}/schema/manifest.rs" ]; then
    fail_with "${mf_dir}/schema/manifest.rs missing"
elif [ ! -f "${mf_dir}/schema/endpoint.rs" ]; then
    fail_with "${mf_dir}/schema/endpoint.rs missing"
elif [ ! -f "${mf_dir}/decode/mod.rs" ]; then
    fail_with "${mf_dir}/decode/mod.rs missing"
elif [ ! -f "${mf_dir}/verify/dispatch.rs" ]; then
    fail_with "${mf_dir}/verify/dispatch.rs missing"
elif ! grep -rq 'payload_hash' "${mf_dir}"; then
    fail_with "${mf_dir} must reference payload_hash"
elif ! grep -rq 'target_triple' "${mf_dir}"; then
    fail_with "${mf_dir} must reference target_triple"
elif grep -rq 'entry_hash' "${mf_dir}"; then
    fail_with "${mf_dir} contains stale entry_hash references"
else
    note ok "capsule manifest v3: schema/decode/verify present"
fi
unset mf_dir

# Forbidden trust-chain naming. We renamed away from "publisher root"
# (now: NØNOS Trust Anchor) and "Dilithium" (now: ML-DSA-65). Any
# lingering reference in trust-chain source is a regression — the
# wire format and the docs must agree.
forbid_dirs="src/security/nonos_trust_anchor src/security/nonos_id_cert src/security/capsule_manifest src/userspace/capsule_proof_io src/fs/ramfs_capsule src/security/keyring_capsule src/security/entropy_capsule src/security/crypto_capsule src/fs/vfs_capsule src/security/market_capsule src/hardware/virtio_rng_capsule src/hardware/ps2_kbd_capsule src/hardware/virtio_blk_capsule src/hardware/virtio_net_capsule src/hardware/xhci_capsule"
forbid_tokens="publisher_root PUBLISHER_ROOT Dilithium DILITHIUM PqSig QuantumSig"
forbid_hits=""
for d in ${forbid_dirs}; do
    [ -d "${d}" ] || continue
    for t in ${forbid_tokens}; do
        if grep -rqI "${t}" "${d}"; then
            forbid_hits="${forbid_hits} ${d}:${t}"
        fi
    done
done
if [ -n "${forbid_hits}" ]; then
    fail_with "forbidden trust-chain tokens present:"
    for h in ${forbid_hits}; do
        echo "  ${h}" >&2
    done
else
    note ok "no forbidden trust-chain tokens (publisher_root / Dilithium / PqSig / QuantumSig)"
fi
unset forbid_dirs forbid_tokens forbid_hits d t h

# Host-side capsule signing tool. Without it nobody can produce a
# manifest the kernel verifier accepts; required for the artifact
# chain to be real.
capsule_sign_dir=nonos-sign/src
if [ ! -d "${capsule_sign_dir}" ]; then
    fail_with "missing ${capsule_sign_dir}"
elif [ ! -f "${capsule_sign_dir}/main.rs" ]; then
    fail_with "${capsule_sign_dir}/main.rs missing"
elif ! grep -q '"capsule-sign"' nonos-sign/Cargo.toml; then
    fail_with "nonos-sign/Cargo.toml must declare the capsule-sign bin"
else
    note ok "capsule-sign host tool present"
fi
unset capsule_sign_dir

# Trust-chain orchestration in the root Makefile. Per-capsule
# cert/manifest rules now live in `nonos-mk/capsule.mk` (one shared
# macro) plus each `userland/<capsule>/Capsule.mk` (metadata only);
# the root Makefile keeps just the trust-anchor policy rule, the
# host-tool target, and an `include` per capsule.
mk=Makefile
expected_includes="userland/capsule_proof_io/Capsule.mk \
                   userland/capsule_ramfs/Capsule.mk \
                   userland/capsule_keyring/Capsule.mk \
                   userland/capsule_entropy/Capsule.mk \
                   userland/capsule_crypto/Capsule.mk \
                   userland/capsule_vfs/Capsule.mk \
                   userland/capsule_market/Capsule.mk \
                   userland/capsule_driver_virtio_rng/Capsule.mk \
                   userland/capsule_driver_ps2_input/Capsule.mk \
                   userland/capsule_driver_virtio_blk/Capsule.mk \
                   userland/capsule_driver_virtio_net/Capsule.mk \
                   userland/capsule_driver_xhci/Capsule.mk"
mk_ok=1
if ! grep -q '\$(NONOS_TRUST_ANCHOR_POLICY_BIN):' "${mk}"; then
    fail_with "${mk} must define a NØNOS trust-anchor policy rule"
    mk_ok=0
elif ! grep -q 'nonos-mk-trust-policy' "${mk}"; then
    fail_with "${mk} must expose nonos-mk-trust-policy"
    mk_ok=0
elif ! grep -q 'nonos-mk-check-trust-keys' "${mk}"; then
    fail_with "${mk} must define nonos-mk-check-trust-keys for missing-seed loud failure"
    mk_ok=0
elif grep -q 'NONOS_PUBLISHER_ROOT_SEED\|publisher_root\.seed\|--root-seed' "${mk}"; then
    fail_with "${mk} contains forbidden publisher_root naming"
    mk_ok=0
fi
if [ "${mk_ok}" -eq 1 ]; then
    for inc in ${expected_includes}; do
        if ! grep -qF "include ${inc}" "${mk}"; then
            fail_with "${mk} must \`include ${inc}\`"
            mk_ok=0
        fi
    done
fi
if [ "${mk_ok}" -eq 1 ]; then
    note ok "root Makefile orchestration: trust-anchor rule + 12 Capsule.mk includes"
fi
unset mk expected_includes mk_ok inc

# nonos-selftest feature wires the in-kernel test runner. handoff
# security is the only group running today; trust-chain test groups
# (nonos_id_cert::all_pass, capsule_manifest::all_pass) are tracked
# follow-ups and will be added back to this gate when they exist.
selftest_runner=src/boot/tests/selftest.rs
if ! grep -q '^nonos-selftest = \[\]' Cargo.toml; then
    fail_with "Cargo.toml must declare the nonos-selftest feature"
elif [ ! -f "${selftest_runner}" ]; then
    fail_with "missing ${selftest_runner}"
elif ! grep -q 'handoff_security::all_pass' "${selftest_runner}"; then
    fail_with "${selftest_runner} must call handoff_security::all_pass()"
else
    note ok "nonos-selftest runner calls handoff_security::all_pass"
fi
unset selftest_runner

# Trust anchor must be baked at compile time. Option/None or empty
# slice fallbacks would let a build ship without a trust anchor and
# then fail open at runtime. include_bytes! turns a missing policy
# file into a build break.
baked=src/security/nonos_trust_anchor/baked.rs
if [ ! -f "${baked}" ]; then
    fail_with "missing ${baked}"
elif ! grep -q 'pub const BAKED_TRUST_ANCHOR_POLICY: &\[u8\]' "${baked}"; then
    fail_with "${baked} must declare BAKED_TRUST_ANCHOR_POLICY as &[u8] (no Option)"
elif ! grep -q 'include_bytes!(".*nonos-data/trust/policy/nonos_trust_anchor\.policy\.bin"' "${baked}"; then
    fail_with "${baked} must include_bytes! nonos-data/trust/policy/nonos_trust_anchor.policy.bin"
elif grep -qE 'Option<&\[u8\]>|= None|: &\[u8\] = &\[\]' "${baked}"; then
    fail_with "${baked} must not carry Option/None or empty-slice trust-anchor fallback"
else
    note ok "BAKED_TRUST_ANCHOR_POLICY is non-optional include_bytes!"
fi
unset baked

# Verified-capsule whitelist. Each capsule listed here must have
# embed.rs include both bytes blobs and spawn.rs construct
# CapsuleSpecVerified routed through spawn_verified — never the
# legacy CapsuleSpec / capsule_spawn::spawn pair. This is the
# allow-list of capsules currently considered verified.
verified_capsules="src/userspace/capsule_proof_io:PROOF_IO src/fs/ramfs_capsule:RAMFS src/security/keyring_capsule:KEYRING src/security/entropy_capsule:ENTROPY src/security/crypto_capsule:CRYPTO src/fs/vfs_capsule:VFS src/security/market_capsule:MARKET src/hardware/virtio_rng_capsule:DRIVER_VIRTIO_RNG src/hardware/ps2_kbd_capsule:DRIVER_PS2_INPUT src/hardware/virtio_blk_capsule:DRIVER_VIRTIO_BLK src/hardware/virtio_net_capsule:DRIVER_VIRTIO_NET src/hardware/xhci_capsule:DRIVER_XHCI src/hardware/e1000_capsule:DRIVER_E1000"
verified_ok=1
for entry in ${verified_capsules}; do
    dir="${entry%:*}"
    prefix="${entry##*:}"
    if [ ! -d "${dir}" ]; then
        fail_with "missing verified-capsule dir ${dir}"
        verified_ok=0
    elif ! grep -q 'CapsuleSpecVerified' "${dir}/spawn.rs"; then
        fail_with "${dir}/spawn.rs must construct CapsuleSpecVerified"
        verified_ok=0
    elif ! grep -q 'capsule_spawn::spawn_verified' "${dir}/spawn.rs"; then
        fail_with "${dir}/spawn.rs must call capsule_spawn::spawn_verified"
        verified_ok=0
    elif grep -qE '\bCapsuleSpec\b[^V]' "${dir}/spawn.rs"; then
        fail_with "${dir}/spawn.rs must not import or use the legacy CapsuleSpec"
        verified_ok=0
    elif grep -qE '\bcapsule_spawn::spawn\b[^_]' "${dir}/spawn.rs"; then
        fail_with "${dir}/spawn.rs must not call the legacy capsule_spawn::spawn"
        verified_ok=0
    elif ! grep -q "${prefix}_NONOS_ID_CERT_BYTES" "${dir}/embed.rs"; then
        fail_with "${dir}/embed.rs must embed ${prefix}_NONOS_ID_CERT_BYTES"
        verified_ok=0
    elif ! grep -q "${prefix}_MANIFEST_BYTES" "${dir}/embed.rs"; then
        fail_with "${dir}/embed.rs must embed ${prefix}_MANIFEST_BYTES"
        verified_ok=0
    fi
done
if [ "${verified_ok}" -eq 1 ]; then
    note ok "verified capsules route through spawn_verified (proof_io, ramfs, keyring, entropy, crypto, vfs, market, driver.virtio_rng, driver.ps2_kbd0, driver.virtio_blk0, driver.virtio_net0, driver.xhci0, driver.e1000_0)"
fi
unset verified_capsules verified_ok entry dir prefix

# nonos-production posture. The legacy unverified spawn path must
# not be reachable; the production / dev-unverified mutex must be
# enforced at compile time.
prod_lib=src/lib.rs
prod_runner=src/kernel_core/process_spawn/capsule_spawn/runner/mod.rs
prod_facade=src/kernel_core/process_spawn/capsule_spawn/mod.rs
prod_spec=src/kernel_core/process_spawn/capsule_spawn/spec.rs
if ! grep -q '^nonos-production = \[\]' Cargo.toml; then
    fail_with "Cargo.toml must declare the nonos-production feature"
elif ! grep -q '^nonos-dev-unverified-capsules = \[\]' Cargo.toml; then
    fail_with "Cargo.toml must declare the nonos-dev-unverified-capsules feature"
elif ! grep -qE 'cfg\(all\(feature = "nonos-production", feature = "nonos-dev-unverified-capsules"\)\)' "${prod_lib}"; then
    fail_with "${prod_lib} must cfg-gate the production/dev-unverified compile_error mutex"
elif ! grep -B1 'mod legacy;' "${prod_runner}" | grep -q 'cfg(not(feature = "nonos-production"))'; then
    fail_with "${prod_runner} must gate mod legacy; on cfg(not(feature = \"nonos-production\"))"
elif ! grep -B1 'pub use legacy::spawn;' "${prod_runner}" | grep -q 'cfg(not(feature = "nonos-production"))'; then
    fail_with "${prod_runner} must gate pub use legacy::spawn on cfg(not(feature = \"nonos-production\"))"
elif ! grep -B1 'pub use runner::spawn;' "${prod_facade}" | grep -q 'cfg(not(feature = "nonos-production"))'; then
    fail_with "${prod_facade} must gate pub use runner::spawn on cfg(not(feature = \"nonos-production\"))"
elif ! grep -B1 'pub use spec::CapsuleSpec;' "${prod_facade}" | grep -q 'cfg(not(feature = "nonos-production"))'; then
    fail_with "${prod_facade} must gate the CapsuleSpec re-export on cfg(not(feature = \"nonos-production\"))"
elif ! grep -B1 'pub struct CapsuleSpec ' "${prod_spec}" | grep -q 'cfg(not(feature = "nonos-production"))'; then
    fail_with "${prod_spec} must gate pub struct CapsuleSpec on cfg(not(feature = \"nonos-production\"))"
else
    note ok "nonos-production gates legacy spawn / CapsuleSpec out and enforces dev-unverified mutex"
fi
unset prod_lib prod_runner prod_facade prod_spec

# Userland driver capsules must use only the NØNOS libc broker
# wrappers — no kernel-internal imports, no inline asm, no Linux
# write/fd surface. New driver capsules should be added to this
# list as they migrate.
driver_capsules="userland/capsule_driver_virtio_rng userland/capsule_driver_ps2_input userland/capsule_driver_virtio_blk userland/capsule_driver_virtio_net userland/capsule_driver_xhci"
driver_ok=1
for d in ${driver_capsules}; do
    [ -d "${d}/src" ] || { fail_with "missing ${d}/src"; driver_ok=0; continue; }
    if grep -rqE '^use crate::drivers|^use crate::memory|^use crate::paging|^use crate::phys|^use crate::hardware' "${d}/src"; then
        fail_with "${d} imports kernel-internal modules (drivers/memory/paging/phys/hardware)"
        driver_ok=0
    elif grep -rq 'asm!' "${d}/src"; then
        fail_with "${d} contains inline asm; capsules go through broker syscalls only"
        driver_ok=0
    elif grep -rqE 'nonos_libc::write\b|sys_write\b' "${d}/src"; then
        fail_with "${d} uses nonos_libc::write / sys_write (Linux-shape compat banned)"
        driver_ok=0
    elif ! grep -rqE 'nonos_libc::mk_(device_list|device_claim|mmio_map|irq_bind|dma_map|pio_grant|ipc_recv)' "${d}/src"; then
        fail_with "${d} must use NØNOS broker wrappers (mk_device_*/mk_mmio_*/mk_irq_*/mk_dma_*/mk_pio_*/mk_ipc_*)"
        driver_ok=0
    fi
done
if [ "${driver_ok}" -eq 1 ]; then
    note ok "userland driver capsules use only NØNOS libc broker wrappers"
fi
unset driver_capsules driver_ok d

# Spawn must install caps through the process authority API, never
# by writing pcb.caps_bits directly. The cap-store gate elsewhere
# in this script restricts pcb.caps_bits writers to process
# internals; the spawn install path joins that contract via
# process::caps::install_spawn.
spawn_install=src/kernel_core/process_spawn/capsule_spawn/runner/install.rs
if [ ! -f "${spawn_install}" ]; then
    fail_with "missing ${spawn_install}"
elif grep -qE 'pcb\.caps_bits\.(store|fetch_or|fetch_and|swap)\b' "${spawn_install}"; then
    fail_with "${spawn_install} must not write pcb.caps_bits directly; use process::caps::install_spawn"
elif ! grep -q 'install_spawn' "${spawn_install}"; then
    fail_with "${spawn_install} must install caps via process::caps::install_spawn"
else
    note ok "spawn install routes caps through process::caps::install_spawn"
fi
unset spawn_install

# Host trust suite must be reachable from the Makefile and must
# execute, not just build. The make target is the contract — the
# kernel-side decoders are validated against the host signer's
# output through these tests.
mk=Makefile
if ! grep -q '^nonos-mk-host-trust-test:' "${mk}"; then
    fail_with "${mk} must define nonos-mk-host-trust-test"
elif ! grep -q 'cargo test --release --test host_trust' "${mk}"; then
    fail_with "${mk} nonos-mk-host-trust-test must run cargo test --release --test host_trust"
else
    note ok "Makefile exposes nonos-mk-host-trust-test for the host signer ↔ kernel verifier proof"
fi
unset mk

# Capsule.mk split — the root Makefile must carry no
# capsule-specific identity, namespace, caps, endpoints, cert
# paths, manifest paths, publisher key prefixes, or signing
# metadata. Those values live in each `userland/<capsule>/Capsule.mk`
# and are materialised by `nonos-mk/capsule.mk`.
shared=nonos-mk/capsule.mk
if [ ! -f "${shared}" ]; then
    fail_with "missing ${shared} (shared capsule build/sign/verify macro)"
elif ! grep -q 'define NONOS_CAPSULE_RULES' "${shared}"; then
    fail_with "${shared} must define the NONOS_CAPSULE_RULES macro"
elif ! grep -q '\$(eval \$(call NONOS_CAPSULE_RULES' "${shared}"; then
    fail_with "${shared} must instantiate NONOS_CAPSULE_RULES via \$(eval \$(call ...))"
else
    note ok "shared capsule macro present at nonos-mk/capsule.mk"
fi
unset shared

# Forbidden capsule-specific declarations in the root Makefile.
# These belong in `userland/<capsule>/Capsule.mk`; carrying them at
# the root reintroduces the monolithic source we just removed.
mk=Makefile
forbidden=
for pat in \
    '^[A-Z_]+_HANDLE\s*:=' \
    '^[A-Z_]+_NS_GLOB\s*:=' \
    '^[A-Z_]+_REQUIRED_CAPS\s*:=' \
    '^[A-Z_]+_OPTIONAL_CAPS\s*:=' \
    '^[A-Z_]+_CAPS_CEILING\s*:=' \
    '^[A-Z_]+_NONOS_ID_CERT_BIN\s*:=' \
    '^[A-Z_]+_MANIFEST_BIN\s*:=' \
    '^[A-Z_]+_REPLY_INBOX\s*:=' \
    '^[A-Z_]+_SERVICE_PORT\s*:=' \
    '^[A-Z_]+_REPLY_PORT\s*:=' \
    '^[A-Z_]+_PUB_ED25519_PREFIX\s*:=' \
    '^[A-Z_]+_PUB_MLDSA65_PREFIX\s*:=' \
    '^[A-Z_]+_NS_GLOB\s*:='; do
    hits=$(grep -nE "${pat}" "${mk}" || true)
    if [ -n "${hits}" ]; then
        forbidden="${forbidden}\n${hits}"
    fi
done
if [ -n "${forbidden}" ]; then
    fail_with "${mk} contains forbidden capsule-specific declarations (must live in Capsule.mk):"
    printf '%b\n' "${forbidden}" | sed 's/^/  /' >&2
else
    note ok "root Makefile carries no capsule-specific identity / caps / endpoints / paths"
fi
unset mk forbidden pat hits

# Every userland capsule directory must own either a `Capsule.mk`
# (verified spawn) or a `Capsule.parked` marker that explains why
# it is not on the verified path.
missing_marker=
for d in userland/capsule_*; do
    [ -d "${d}" ] || continue
    if [ ! -f "${d}/Capsule.mk" ] && [ ! -f "${d}/Capsule.parked" ]; then
        missing_marker="${missing_marker} ${d}"
    fi
done
if [ -n "${missing_marker}" ]; then
    fail_with "userland capsule directories without Capsule.mk or Capsule.parked:"
    for d in ${missing_marker}; do
        echo "  ${d}" >&2
    done
else
    note ok "every userland capsule directory has Capsule.mk or Capsule.parked"
fi
unset missing_marker d

# Each verified capsule directory's `Capsule.mk` must declare the
# full identity surface the macro consumes. Missing fields would
# silently fall back to defaults and ship a half-wired capsule.
required_fields="CAPSULE_SLUG CAPSULE_HANDLE CAPSULE_DOMAIN CAPSULE_DIR \
                 CAPSULE_BIN_NAME CAPSULE_FEATURE CAPSULE_NAMESPACE \
                 CAPSULE_SERVICE_ENDPOINT CAPSULE_REPLY_ENDPOINT \
                 CAPSULE_REQUIRED_CAPS CAPSULE_KERNEL_MIRROR"
mk_complete=1
for cap_mk in userland/capsule_*/Capsule.mk; do
    [ -f "${cap_mk}" ] || continue
    if ! grep -q '^include nonos-mk/capsule.mk' "${cap_mk}"; then
        fail_with "${cap_mk} must end with: include nonos-mk/capsule.mk"
        mk_complete=0
        continue
    fi
    for fld in ${required_fields}; do
        if ! grep -qE "^${fld}\s*:=" "${cap_mk}"; then
            fail_with "${cap_mk} must declare ${fld}"
            mk_complete=0
        fi
    done
done
if [ "${mk_complete}" -eq 1 ]; then
    note ok "every Capsule.mk declares the full identity surface"
fi
unset required_fields mk_complete cap_mk fld

# Committed baked-trust bundle under nonos-data/trust/. The
# kernel verifier reads the policy + per-capsule cert + manifest
# straight out of this directory at compile time (`include_bytes!`)
# and at runtime (decode + verify in `spawn_verified`). CI's
# host-trust lane verifies these committed bytes against the host
# signer; production key custody is still pending until the HSM /
# offline ceremony slice lands.
trust_dir=nonos-data/trust
trust_ok=1
if [ ! -f "${trust_dir}/policy/nonos_trust_anchor.policy.bin" ]; then
    fail_with "missing ${trust_dir}/policy/nonos_trust_anchor.policy.bin"
    trust_ok=0
fi
if [ ! -f "${trust_dir}/MANIFEST.sha256" ]; then
    fail_with "missing ${trust_dir}/MANIFEST.sha256 (regenerate via shasum -a 256 over the committed set)"
    trust_ok=0
fi
if [ ! -f "${trust_dir}/CEREMONY.md" ]; then
    fail_with "missing ${trust_dir}/CEREMONY.md (custody status + ceremony metadata)"
    trust_ok=0
fi
for ta in nonos_trust_anchor_ed25519.pub nonos_trust_anchor_mldsa65.pub ; do
    if [ ! -f "${trust_dir}/keys/${ta}" ]; then
        fail_with "missing ${trust_dir}/keys/${ta}"
        trust_ok=0
    fi
done
stale_markers=
for bin in proof_io ramfs keyring entropy crypto vfs market \
           driver_virtio_rng driver_ps2_input \
           driver_virtio_blk driver_virtio_net \
           driver_xhci driver_e1000 ; do
    if [ ! -f "${trust_dir}/keys/${bin}_publisher_ed25519.pub" ]; then
        fail_with "missing ${trust_dir}/keys/${bin}_publisher_ed25519.pub"
        trust_ok=0
    fi
    if [ ! -f "${trust_dir}/keys/${bin}_publisher_mldsa65.pub" ]; then
        fail_with "missing ${trust_dir}/keys/${bin}_publisher_mldsa65.pub"
        trust_ok=0
    fi
    if [ ! -f "${trust_dir}/capsules/${bin}.nonos_id_cert.bin" ]; then
        fail_with "missing ${trust_dir}/capsules/${bin}.nonos_id_cert.bin"
        trust_ok=0
    fi
    if [ ! -f "${trust_dir}/capsules/${bin}.manifest.bin" ]; then
        fail_with "missing ${trust_dir}/capsules/${bin}.manifest.bin"
        trust_ok=0
    fi
    if [ -f "${trust_dir}/capsules/${bin}.STALE" ]; then
        stale_markers="${stale_markers} ${bin}"
    fi
done
if [ "${trust_ok}" -eq 1 ]; then
    if [ -n "${stale_markers}" ]; then
        # STALE markers are CI metadata only — the kernel verifier
        # never honours them. They suspend the on-disk artifacts
        # test's ELF↔manifest binding check while a freshly-rebuilt
        # ELF awaits a re-sign. Allowed on dev branches; forbidden
        # on `main` because a merged STALE bundle would CI-pass
        # while the kernel would fail at runtime.
        branch=
        if [ -n "${GITHUB_REF:-}" ]; then
            case "${GITHUB_REF}" in
                refs/heads/*) branch="${GITHUB_REF#refs/heads/}" ;;
                *)            branch="${GITHUB_REF}" ;;
            esac
        elif command -v git >/dev/null 2>&1 && \
             git rev-parse --is-inside-work-tree >/dev/null 2>&1 ; then
            branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
        else
            branch=unknown
        fi
        case "${branch}" in
            main|refs/heads/main)
                fail_with "STALE markers forbidden on main; capsules with stale baked artifacts:${stale_markers}"
                fail_with "  re-sign each capsule via \`make nonos-mk-<slug>-sign\` and remove the .STALE marker before merging to main"
                ;;
            *)
                # Dev / PR branch — surface but do not fail.
                # `note ok` would understate it; emit an explicit
                # warning that propagates up the CI log.
                echo "::warning::STALE markers present on branch '${branch}':${stale_markers} — must be cleared before merging to main" >&2
                note ok "baked trust bundle present (policy / digest manifest / 13 cert+manifest pairs / publisher pubs); STALE on branch '${branch}':${stale_markers}"
                ;;
        esac
        unset branch
    else
        note ok "baked trust bundle present (policy / digest manifest / 13 cert+manifest pairs / publisher pubs)"
    fi
fi
unset trust_dir trust_ok stale_markers ta bin

# No seed files may be tracked by git. The host signer's seeds
# live in `.keys/` (gitignored); pubs live under nonos-data/trust/.
# A leaked seed is a custody breach.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    leaked=$(git ls-files '*.seed' 2>/dev/null || true)
    if [ -n "${leaked}" ]; then
        fail_with "seed files tracked by git (custody breach):"
        printf '  %s\n' ${leaked} >&2
    else
        note ok "no .seed files tracked by git"
    fi
    unset leaked
else
    # Outside a git checkout — fall back to a filesystem scan that
    # excludes ignored caches.
    leaked=$(find . -type f -name '*.seed' \
             -not -path './target/*' \
             -not -path './*/target/*' \
             -not -path './.keys/*' \
             2>/dev/null || true)
    if [ -n "${leaked}" ]; then
        fail_with "seed files outside .keys/ (custody breach):"
        printf '  %s\n' ${leaked} >&2
    else
        note ok "no .seed files outside .keys/ (no git context)"
    fi
    unset leaked
fi

# Trust-chain CI workflow. Two distinct proof lanes (scratch
# ceremony + baked artifact) plus the static gates and the cargo
# matrix; covers the host signer ↔ kernel verifier surface CI was
# missing. Seed files must never reach uploaded artifacts.
trust_wf=.github/workflows/nonos-trust-chain.yml
baseline_wf=.github/workflows/microkernel-baseline.yml
wf_ok=1
if [ ! -f "${trust_wf}" ]; then
    fail_with "missing ${trust_wf}"
    wf_ok=0
elif ! grep -q 'bash nonos-ci/run-static-checks.sh' "${trust_wf}"; then
    fail_with "${trust_wf} must run \`bash nonos-ci/run-static-checks.sh\`"
    wf_ok=0
elif ! grep -q 'make nonos-mk-host-trust-test' "${trust_wf}"; then
    fail_with "${trust_wf} must run \`make nonos-mk-host-trust-test\`"
    wf_ok=0
elif ! grep -q 'Refuse to upload seed files' "${trust_wf}"; then
    fail_with "${trust_wf} must include a \"Refuse to upload seed files\" guard step"
    wf_ok=0
elif ! perl -0777 -e '
    my $src = do { local $/; <STDIN> };
    # For each `uses: actions/upload-artifact` step, locate the
    # following `with:` block and the `path:` argument inside it.
    while ($src =~ /uses:\s*actions\/upload-artifact[^\n]*\n((?:[ \t]+[^\n]*\n)+)/g) {
        my $block = $1;
        # Inline form: `path: foo`
        if ($block =~ /^[ \t]+path:[ \t]+([^\n|][^\n]*)/m) {
            my $p = $1;
            if ($p =~ /\.seed/) {
                print "LEAK: inline path includes .seed: $p\n";
                exit 1;
            }
            next;
        }
        # Literal-block form: `path: |\n  ...`
        if ($block =~ /^([ \t]+)path:[ \t]*\|[ \t]*\n((?:\1[ \t]+[^\n]*\n)+)/m) {
            my $paths = $2;
            if ($paths =~ /\.seed/) {
                print "LEAK: upload path block includes .seed:\n$paths";
                exit 1;
            }
        }
    }
    exit 0;
' < "${trust_wf}" ; then
    fail_with "${trust_wf} upload-artifact step lists .seed files"
    wf_ok=0
fi
if [ "${wf_ok}" -eq 1 ]; then
    for slug in proof-io ramfs keyring entropy crypto vfs market \
                driver-virtio-rng driver-ps2-input \
                driver-virtio-blk driver-virtio-net driver-xhci \
                driver-e1000 ; do
        if ! grep -q "${slug}" "${trust_wf}"; then
            fail_with "${trust_wf} must reference verified capsule slug \`${slug}\`"
            wf_ok=0
        fi
    done
fi
if [ "${wf_ok}" -eq 1 ]; then
    if [ ! -f "${baseline_wf}" ]; then
        fail_with "missing ${baseline_wf}"
        wf_ok=0
    elif ! grep -q 'bash nonos-ci/run-static-checks.sh' "${baseline_wf}"; then
        fail_with "${baseline_wf} must also run \`bash nonos-ci/run-static-checks.sh\` so static gates run on every push/PR"
        wf_ok=0
    fi
fi
if [ "${wf_ok}" -eq 1 ]; then
    note ok "trust-chain workflow runs static gates + host-trust + scratch lane for all 13 capsules"
fi
unset trust_wf baseline_wf wf_ok slug

# Every verified-capsule entry in the verified-capsules gate above
# must have a matching `Capsule.mk`. Catches the case where a new
# capsule joins the kernel-side gate but never gets a Capsule.mk.
mismatch=
for entry in src/userspace/capsule_proof_io:userland/capsule_proof_io \
             src/fs/ramfs_capsule:userland/capsule_ramfs \
             src/security/keyring_capsule:userland/capsule_keyring \
             src/security/entropy_capsule:userland/capsule_entropy \
             src/security/crypto_capsule:userland/capsule_crypto \
             src/fs/vfs_capsule:userland/capsule_vfs \
             src/security/market_capsule:userland/capsule_market \
             src/hardware/virtio_rng_capsule:userland/capsule_driver_virtio_rng \
             src/hardware/ps2_kbd_capsule:userland/capsule_driver_ps2_input \
             src/hardware/virtio_blk_capsule:userland/capsule_driver_virtio_blk \
             src/hardware/virtio_net_capsule:userland/capsule_driver_virtio_net \
             src/hardware/xhci_capsule:userland/capsule_driver_xhci; do
    kernel_dir="${entry%:*}"
    user_dir="${entry##*:}"
    if [ -d "${kernel_dir}" ] && [ ! -f "${user_dir}/Capsule.mk" ]; then
        mismatch="${mismatch} ${kernel_dir}->${user_dir}"
    fi
done
if [ -n "${mismatch}" ]; then
    fail_with "verified-capsule kernel mirrors lack matching Capsule.mk:"
    for m in ${mismatch}; do
        echo "  ${m}" >&2
    done
else
    note ok "every verified-capsule kernel mirror has a matching Capsule.mk"
fi
unset mismatch entry kernel_dir user_dir m

# Broker IRQ vector pool. The pool size is wired into IDT install,
# IO-APIC reservation, slot table, and per-vector ISR stubs; if any
# constant drifts the kernel will still build but grants will land
# on the wrong vectors. Pin the constants here so a silent change
# trips the gate instead of producing weird IRQ behaviour at boot.
broker_vec_file="src/arch/x86_64/interrupt/broker/vectors.rs"
if [ ! -f "${broker_vec_file}" ]; then
    fail_with "missing ${broker_vec_file}"
else
    if ! grep -Fxq 'pub const BROKER_VEC_MIN: u8 = 0x81;' "${broker_vec_file}"; then
        fail_with "${broker_vec_file} must declare BROKER_VEC_MIN = 0x81"
    fi
    if ! grep -Fxq 'pub const BROKER_VEC_MAX: u8 = 0xC0;' "${broker_vec_file}"; then
        fail_with "${broker_vec_file} must declare BROKER_VEC_MAX = 0xC0"
    fi
    if ! grep -Fq 'BROKER_VEC_COUNT == 64' "${broker_vec_file}"; then
        fail_with "${broker_vec_file} must keep the const-assert BROKER_VEC_COUNT == 64"
    fi
fi
broker_isr_file="src/arch/x86_64/interrupt/broker/isr.rs"
if [ ! -f "${broker_isr_file}" ]; then
    fail_with "missing ${broker_isr_file}"
else
    isr_stub_count="$(grep -c '^broker_irq_stub!' "${broker_isr_file}" || true)"
    if [ "${isr_stub_count}" != "64" ]; then
        fail_with "${broker_isr_file} must declare 64 broker_irq_stub! entries (got ${isr_stub_count})"
    else
        note ok "broker IRQ pool: 64 vectors at 0x81..0xC0, 64 ISR stubs"
    fi
fi
unset broker_vec_file broker_isr_file isr_stub_count

# IRQ bind flags. The kernel and the userland libc must agree on
# the bit value of `BIND_MSIX`; if they drift, capsules either get
# silent INTx fallback or trip an UnsupportedFlags error in the
# kernel. The constant is small and rarely touched so an exact-line
# pin is enough.
broker_types_file="src/hardware/broker/irq/types.rs"
libc_irq_file="userland/libc/src/broker/irq.rs"
if [ ! -f "${broker_types_file}" ]; then
    fail_with "missing ${broker_types_file}"
elif ! grep -Fxq 'pub const BIND_MSIX: u32 = 1 << 0;' "${broker_types_file}"; then
    fail_with "${broker_types_file} must declare BIND_MSIX = 1 << 0"
fi
if [ ! -f "${libc_irq_file}" ]; then
    fail_with "missing ${libc_irq_file}"
elif ! grep -Fxq 'pub const MK_IRQ_BIND_MSIX: u32 = 1 << 0;' "${libc_irq_file}"; then
    fail_with "${libc_irq_file} must declare MK_IRQ_BIND_MSIX = 1 << 0 (must match kernel BIND_MSIX)"
else
    note ok "BIND_MSIX flag bit pinned in kernel and libc"
fi
unset broker_types_file libc_irq_file

# PCI config-write allowlist constants. Capsules can only legally
# write three bits across two registers; if either side drifts the
# guard either over-permits (capsule writes a register the kernel
# would have rejected, but now does not) or under-permits (capsule's
# wrapper rejects a value the kernel would have accepted, breaking
# the userland API). Pin the constants on both sides so the gate
# trips before either of those slip in.
pci_constants_file="src/drivers/pci/constants/registers.rs"
pci_msi_constants="src/drivers/pci/constants/msi.rs"
libc_pci_file="userland/libc/src/broker/pci.rs"
if [ ! -f "${pci_constants_file}" ]; then
    fail_with "missing ${pci_constants_file}"
elif ! grep -Fxq 'pub const CFG_COMMAND: u16 = 0x04;' "${pci_constants_file}"; then
    fail_with "${pci_constants_file} must declare CFG_COMMAND = 0x04"
elif ! grep -Fxq 'pub const CMD_BUS_MASTER: u16 = 1 << 2;' "${pci_constants_file}"; then
    fail_with "${pci_constants_file} must declare CMD_BUS_MASTER = 1 << 2"
fi
if [ ! -f "${pci_msi_constants}" ]; then
    fail_with "missing ${pci_msi_constants}"
elif ! grep -Fxq 'pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;' "${pci_msi_constants}"; then
    fail_with "${pci_msi_constants} must declare MSIX_CTRL_ENABLE = 1 << 15"
elif ! grep -Fxq 'pub const MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;' "${pci_msi_constants}"; then
    fail_with "${pci_msi_constants} must declare MSIX_CTRL_FUNCTION_MASK = 1 << 14"
fi
if [ ! -f "${libc_pci_file}" ]; then
    fail_with "missing ${libc_pci_file}"
elif ! grep -Fxq 'pub const MK_PCI_CFG_COMMAND: u32 = 0x04;' "${libc_pci_file}"; then
    fail_with "${libc_pci_file} must declare MK_PCI_CFG_COMMAND = 0x04"
elif ! grep -Fxq 'pub const MK_PCI_CMD_BUS_MASTER: u16 = 1 << 2;' "${libc_pci_file}"; then
    fail_with "${libc_pci_file} must declare MK_PCI_CMD_BUS_MASTER = 1 << 2"
elif ! grep -Fxq 'pub const MK_PCI_MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;' "${libc_pci_file}"; then
    fail_with "${libc_pci_file} must declare MK_PCI_MSIX_CTRL_FUNCTION_MASK = 1 << 14"
elif ! grep -Fxq 'pub const MK_PCI_MSIX_CTRL_ENABLE: u16 = 1 << 15;' "${libc_pci_file}"; then
    fail_with "${libc_pci_file} must declare MK_PCI_MSIX_CTRL_ENABLE = 1 << 15"
else
    note ok "PCI config-write allowlist constants pinned in kernel and libc"
fi
unset pci_constants_file pci_msi_constants libc_pci_file

# `MkPciConfigWrite` syscall tag. The 4-byte `MPCW` ASCII identifier
# binds the kernel handler to the libc wrapper through the tag4
# numeric ABI; if either side drifts, the capsule either gets ENOSYS
# from an unknown tag or the kernel routes someone else's tag into
# the PCI write handler.
kern_numbers_file="src/syscall/microkernel/numbers.rs"
libc_numbers_file="userland/libc/src/syscall/numbers/mod.rs"
if [ ! -f "${kern_numbers_file}" ]; then
    fail_with "missing ${kern_numbers_file}"
elif ! grep -Fxq 'pub const SYS_PCI_CONFIG_WRITE: u64 = tag4(b"MPCW");' "${kern_numbers_file}"; then
    fail_with "${kern_numbers_file} must declare SYS_PCI_CONFIG_WRITE = tag4(b\"MPCW\")"
fi
if [ ! -f "${libc_numbers_file}" ]; then
    fail_with "missing ${libc_numbers_file}"
elif ! grep -Fxq 'pub(crate) const N_MK_PCI_CONFIG_WRITE: i64 = tag4(b"MPCW");' "${libc_numbers_file}"; then
    fail_with "${libc_numbers_file} must declare N_MK_PCI_CONFIG_WRITE = tag4(b\"MPCW\")"
else
    note ok "MkPciConfigWrite tag4 'MPCW' pinned in kernel and libc"
fi
unset kern_numbers_file libc_numbers_file

# Libc public surface for `mk_pci_config_write`. The wrapper must
# be re-exported from `lib.rs` together with the four allowlist
# constants so a capsule never has to reach into the broker
# submodule to find them. A removed export here would make it look
# like the API was retracted while the syscall tag stayed live.
libc_lib_file="userland/libc/src/lib.rs"
if [ ! -f "${libc_lib_file}" ]; then
    fail_with "missing ${libc_lib_file}"
else
    libc_lib_missing=""
    for sym in mk_pci_config_write MK_PCI_CFG_COMMAND MK_PCI_CMD_BUS_MASTER \
        MK_PCI_MSIX_CTRL_FUNCTION_MASK MK_PCI_MSIX_CTRL_ENABLE; do
        if ! grep -Fq "${sym}" "${libc_lib_file}"; then
            libc_lib_missing="${libc_lib_missing} ${sym}"
        fi
    done
    if [ -n "${libc_lib_missing}" ]; then
        fail_with "${libc_lib_file} must re-export:${libc_lib_missing}"
    else
        note ok "libc lib.rs surfaces mk_pci_config_write and the 4 PCI allowlist constants"
    fi
    unset libc_lib_missing
fi
unset libc_lib_file

# No alternative PCI config-write primitive may exist on the
# capsule-facing surface. Userland libc must export exactly one
# `#[no_mangle]` PCI write symbol — `mk_pci_config_write`. A
# generic `mk_pci_write` / `mk_pci_config_write_*` would silently
# bypass the allowlist; this gate makes that an audit failure.
libc_pci_no_mangle_count="$(grep -c '#\[no_mangle\]' userland/libc/src/broker/pci.rs 2>/dev/null | tr -d '[:space:]')"
if [ "${libc_pci_no_mangle_count}" != "1" ]; then
    fail_with "userland/libc/src/broker/pci.rs must declare exactly one #[no_mangle] symbol (got ${libc_pci_no_mangle_count})"
fi
extra_libc_pci_writers="$(grep -RIn 'pub extern "C" fn mk_pci' userland/libc/src 2>/dev/null | grep -v 'mk_pci_config_write\b' || true)"
if [ -n "${extra_libc_pci_writers}" ]; then
    fail_with "additional capsule-facing PCI write symbols detected in userland/libc/src:"
    echo "${extra_libc_pci_writers}" >&2
fi
extra_kern_pci_handlers="$(grep -RIn 'fn sys_pci' src/syscall 2>/dev/null | grep -v 'sys_pci_config_write\b' || true)"
if [ -n "${extra_kern_pci_handlers}" ]; then
    fail_with "additional sys_pci_* syscall handlers detected:"
    echo "${extra_kern_pci_handlers}" >&2
fi
if [ "${libc_pci_no_mangle_count}" = "1" ] && [ -z "${extra_libc_pci_writers}" ] \
    && [ -z "${extra_kern_pci_handlers}" ]; then
    note ok "mk_pci_config_write is the only capsule-facing PCI write surface"
fi
unset libc_pci_no_mangle_count extra_libc_pci_writers extra_kern_pci_handlers

# Capsule must not be able to map the MSI-X table or PBA region
# into its address space. The mmio bind path enforces this through
# `msix_exclusion::validate`; gate that the validator file exists,
# is invoked from `map.rs`, and that no `#[no_mangle]` libc surface
# exposes a direct MSI-X table or BAR programming primitive.
mmio_excl_file="src/hardware/broker/mmio/msix_exclusion.rs"
mmio_map_file="src/hardware/broker/mmio/map.rs"
if [ ! -f "${mmio_excl_file}" ]; then
    fail_with "missing ${mmio_excl_file}"
fi
if [ ! -f "${mmio_map_file}" ]; then
    fail_with "missing ${mmio_map_file}"
elif ! grep -Fq 'msix_exclusion::validate' "${mmio_map_file}"; then
    fail_with "${mmio_map_file} must call msix_exclusion::validate before mapping a BAR slice"
fi
forbidden_libc_msix="$(grep -RIn 'pub extern "C" fn mk_msix\|pub extern "C" fn mk_bar' userland/libc/src 2>/dev/null || true)"
if [ -n "${forbidden_libc_msix}" ]; then
    fail_with "capsule-facing MSI-X table or BAR programming primitive detected:"
    echo "${forbidden_libc_msix}" >&2
fi
if [ -f "${mmio_excl_file}" ] && grep -Fq 'msix_exclusion::validate' "${mmio_map_file}" \
    && [ -z "${forbidden_libc_msix}" ]; then
    note ok "MSI-X table + PBA exclusion wired into mmio_map; no capsule-facing direct programming surface"
fi
unset mmio_excl_file mmio_map_file forbidden_libc_msix

if [ "${fail}" -ne 0 ]; then
    echo
    echo "static-checks: FAIL"
    exit 1
fi

echo
echo "static-checks: PASS"
