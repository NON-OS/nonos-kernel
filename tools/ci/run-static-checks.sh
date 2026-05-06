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

if [ "${fail}" -ne 0 ]; then
    echo
    echo "static-checks: FAIL"
    exit 1
fi

echo
echo "static-checks: PASS"
