#!/usr/bin/env bash
# Symbol scan for the microkernel image. Pairs with the Makefile target
# `microkernel-symbol-scan` (legacy storage/desktop/network list) and
# adds the trusted-path absences: keyring syscalls, in-kernel TCP/IP,
# legacy tty / HID / module loader, and the in-kernel onion stack.
# A hit means a gated module leaked back into the trusted path.

set -euo pipefail

bin="${1:-target/x86_64-nonos/release/nonos-kernel}"

if [ ! -f "${bin}" ]; then
    echo "::error::microkernel binary not found at ${bin}" >&2
    exit 1
fi

forbidden=(
    'syscall::keyring|nonos_kernel::syscall::keyring'
    'crate::tty|nonos_kernel::tty::'
    'crate::network::stack|nonos_kernel::network::stack::'
    'crate::network::onion|nonos_kernel::network::onion::'
    'crate::input|nonos_kernel::input::'
    'crate::modules|nonos_kernel::modules::'
)

if nm --demangle "${bin}" >/dev/null 2>&1; then
    nm_cmd=(nm --demangle "${bin}")
else
    nm_cmd=(nm "${bin}")
fi

dump="$(mktemp)"
trap 'rm -f "${dump}"' EXIT
"${nm_cmd[@]}" 2>/dev/null > "${dump}"

fail=0
for entry in "${forbidden[@]}"; do
    label="${entry%%|*}"
    pattern="${entry#*|}"
    hits="$(grep -F "${pattern}" "${dump}" | head -3 || true)"
    if [ -n "${hits}" ]; then
        echo "::error::microkernel image leaks symbols for '${label}'"
        echo "${hits}"
        fail=1
    fi
done

if [ "${fail}" -ne 0 ]; then
    exit 1
fi

echo "PASS: extended symbol scan clean for ${bin}"
