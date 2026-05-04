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

cfg_count="$(grep -rn 'cfg(target_arch' src --include='*.rs' | grep -v '^src/arch/' | wc -l | tr -d '[:space:]')"
run_baseline 'cfg(target_arch) outside src/arch' "${baselines_dir}/cfg-target-arch-count.txt" "${cfg_count}"

mem_count="$(grep -rn 'crate::mem::' src --include='*.rs' | wc -l | tr -d '[:space:]')"
run_baseline 'crate::mem::* use sites' "${baselines_dir}/crate-mem-uses.txt" "${mem_count}"

sched_count="$(grep -rn 'crate::sched::' src --include='*.rs' | wc -l | tr -d '[:space:]')"
run_baseline 'crate::sched::* use sites' "${baselines_dir}/crate-sched-uses.txt" "${sched_count}"

if [ "${fail}" -ne 0 ]; then
    echo
    echo "static-checks: FAIL"
    exit 1
fi

echo
echo "static-checks: PASS"
