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
src/userspace/init/supervisor/mod.rs \
src/userspace/init/supervisor/loop_impl.rs \
src/userspace/init/supervisor/supervision.rs \
src/userspace/init/supervisor/verification.rs"
forbidden_pattern='crate::(agents|apps|daemon|display|graphics|input|lang|locale|modules|monitor|network|nox|npkg|persistence|runtime|sdk|shell|storage|tty|vault|zk_engine|zksync)::|crate::services::[a-z0-9_]+_engine::|crate::syscall::(extended|aio|splice|bpf|ptrace|robust_futex|rseq|seccomp|mqueue|namespace|pkey|process_vm|xattr|fanotify|vdso|cgroup|capsule|keyring|graphics_surface)::'
init_dirty="$( { grep -nE "${forbidden_pattern}" ${init_files} 2>/dev/null || true; } )"
if [ -n "${init_dirty}" ]; then
    fail_with "production init references a deleted root"
    printf '%s\n' "${init_dirty}" >&2
else
    note ok "production init free of deleted-root references"
fi

if [ "${fail}" -ne 0 ]; then
    echo
    echo "static-checks: FAIL"
    exit 1
fi

echo
echo "static-checks: PASS"
