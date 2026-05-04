#!/usr/bin/env bash
# Binary hygiene scan over a built kernel ELF. Looks for leaked
# secret-shaped strings, debug markers, and common signs of build
# state that should never reach a release artefact.
#
# Usage: scan-binary-hygiene.sh <path-to-kernel-elf>

set -euo pipefail

bin="${1:-target/x86_64-nonos/release/nonos-kernel}"

if [ ! -f "${bin}" ]; then
    echo "::error::binary not found at ${bin}" >&2
    exit 1
fi

dump="$(mktemp)"
trap 'rm -f "${dump}"' EXIT
strings -n 8 "${bin}" > "${dump}"

# Forbidden patterns. Each line: '<label>|<grep -E pattern>'.
patterns=(
    'private-key block|-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
    'aws-access-key-id|AKIA[0-9A-Z]{16}'
    'github-token|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}'
    'slack-token|xox[abprs]-[0-9A-Za-z-]{10,}'
    'ssh-private-marker|ssh-rsa AAAA|ssh-ed25519 AAAA'
    'plaintext-password|password\s*[:=]\s*[A-Za-z0-9]{6,}'
    'TODO_SECURITY marker|TODO[ _-]?SECURITY|FIXME[ _-]?SECURITY|XXX[ _-]?SECURITY'
)

fail=0
for entry in "${patterns[@]}"; do
    label="${entry%%|*}"
    pattern="${entry#*|}"
    hits="$(grep -E "${pattern}" "${dump}" | head -3 || true)"
    if [ -n "${hits}" ]; then
        echo "::error::binary leaks pattern '${label}'"
        echo "${hits}"
        fail=1
    fi
done

if [ "${fail}" -ne 0 ]; then
    exit 1
fi

echo "PASS: binary-hygiene clean for ${bin}"
