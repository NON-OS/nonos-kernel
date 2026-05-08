#!/usr/bin/env bash
# Static gates that microkernel-baseline.yml::static-checks runs.
# Same script for local and CI; a green run here means the gate passes.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${repo_root}"

cargo_toml="Cargo.toml"
baselines_dir="tools/ci/baselines"
helper="tools/ci/check-baseline.sh"
profiles_check="tools/ci/check-feature-profiles.py"

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
mmio_handler_leak="$( { grep -rn 'sys_mmio_map\|sys_mmio_unmap\|MkMmioMap\|MkMmioUnmap' src --include='*.rs' || true; } | { grep -v '^src/syscall/microkernel/' || true; } | { grep -v '^src/syscall/contract/cap_table/mk.rs:' || true; } | { grep -v '^src/syscall/dispatch/router/mod.rs:' || true; } | { grep -v '^src/syscall/numbers/' || true; } | { grep -v '^src/hardware/broker/' || true; } )"
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
if ! grep -q '^name = "marketplace-index"' tools/Cargo.toml; then
    fail_with "tools/Cargo.toml missing [[bin]] marketplace-index"
elif [ ! -f tools/src/marketplace_index/main.rs ]; then
    fail_with "tools/src/marketplace_index/main.rs missing"
else
    note ok "marketplace-index CLI declared and source present"
fi

# The CLI must encode through nonos_marketplace_abi, not by
# hand-rolling NOX0/JSON/fixed-trailer wire bytes. A grep for
# legacy wrapper magic in the tool source guards against the
# CLI drifting from the canonical codec.
mk_tool_drift="$( { grep -rnE 'b?"NOX0"|"index_signature":|fixed_trailer|trailer_v[0-9]' tools/src/marketplace_index --include='*.rs' || true; } | { grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true; } )"
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
    libc_mmap="$(grep -E '^pub(\([^)]*\))? const N_MMAP: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    libc_exit="$(grep -E '^pub(\([^)]*\))? const N_EXIT: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    libc_yield="$(grep -E '^pub(\([^)]*\))? const N_MK_YIELD: i64 = ' ${libc_numbers} | sed 's/.*= //; s/;.*//')"
    kern_mmap="$(grep -E '^pub const SYS_MMAP: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"
    kern_exit="$(grep -E '^pub const SYS_EXIT: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"
    kern_yield="$(grep -E '^pub const SYS_YIELD: u64 = ' src/syscall/microkernel/numbers.rs | sed 's/.*= //; s/;.*//')"

    abi_drift=0
    if [ "${libc_mmap}" != "${kern_mmap}" ]; then
        fail_with "ABI drift: libc N_MMAP=${libc_mmap} vs kernel SYS_MMAP=${kern_mmap}"
        abi_drift=1
    fi
    if [ "${libc_exit}" != "${kern_exit}" ]; then
        fail_with "ABI drift: libc N_EXIT=${libc_exit} vs kernel SYS_EXIT=${kern_exit}"
        abi_drift=1
    fi
    if [ "${libc_yield}" != "${kern_yield}" ]; then
        fail_with "ABI drift: libc N_MK_YIELD=${libc_yield} vs kernel SYS_YIELD=${kern_yield}"
        abi_drift=1
    fi
    if [ "${abi_drift}" -eq 0 ]; then
        note ok "libc N_MMAP / N_EXIT / N_MK_YIELD match kernel SYS_*"
    fi
    unset libc_numbers libc_mmap libc_exit libc_yield kern_mmap kern_exit kern_yield abi_drift
fi
unset libc_syscall_dir

# Capability namespace invariant. `pcb.caps_bits` is decoded by the
# syscall contract against `crate::capabilities::Capability`. The
# legacy `process::capabilities::Capability` enum (Exit, Read, Write,
# Fork, ...) shares the same u64 column and aliases by accident — its
# `UseCrypto` (1<<8) lands on the new `Debug` (also 1<<8). Storing or
# inheriting bits from the legacy enum would silently grant the
# wrong authority. The producers below are allowed to call the
# legacy preset/check helpers; nothing else may.
legacy_preset_callers="$( { grep -RInE '\b(standard_user_capabilities|privileged_capabilities|system_capabilities|sandboxed_capabilities|network_service_capabilities|full_capabilities)\(\)\.bits\(\)' src --include='*.rs' \
    | grep -v 'src/process/capabilities/' \
    | grep -v 'src/process/capabilities/tests/' \
    || true; } )"
if [ -n "${legacy_preset_callers}" ]; then
    fail_with "process::capabilities preset bits flow into a u64 outside the legacy module"
    printf '%s\n' "${legacy_preset_callers}" >&2
else
    note ok "no caller routes process::capabilities::*Capabilities().bits() into u64"
fi
unset legacy_preset_callers

legacy_enum_leak="$( { grep -RInE 'process::capabilities::Capability\b|use crate::process::capabilities::' src --include='*.rs' \
    | grep -v 'src/process/capabilities/' \
    || true; } )"
if [ -n "${legacy_enum_leak}" ]; then
    fail_with "legacy process::capabilities::Capability referenced outside its module"
    printf '%s\n' "${legacy_enum_leak}" >&2
else
    note ok "legacy process::capabilities::Capability stays inside its module"
fi
unset legacy_enum_leak

legacy_in_syscall="$( { grep -RIn 'crate::process::capabilities::' src/syscall --include='*.rs' || true; } )"
if [ -n "${legacy_in_syscall}" ]; then
    fail_with "syscall contract imports process::capabilities — must use crate::capabilities only"
    printf '%s\n' "${legacy_in_syscall}" >&2
else
    note ok "syscall contract free of legacy process::capabilities imports"
fi
unset legacy_in_syscall

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
    -not -path './tools/target/*' -not -path './userland/*/target/*' \
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

if [ "${fail}" -ne 0 ]; then
    echo
    echo "static-checks: FAIL"
    exit 1
fi

echo
echo "static-checks: PASS"
