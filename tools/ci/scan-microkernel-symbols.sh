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

# ELF shape. The static upper-half kernel carries no .dynamic
# section and no relocations. PIE / dynamic linking would mean
# the kernel re-relocates itself at boot, which we do not do.

readelf_bin=""
for cand in llvm-readelf readelf; do
    if command -v "${cand}" >/dev/null 2>&1; then
        readelf_bin="${cand}"
        break
    fi
done

if [ -z "${readelf_bin}" ] && command -v rustc >/dev/null 2>&1; then
    host="$(rustc -vV 2>/dev/null | awk '/host:/{print $2}')"
    active="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}')"
    if [ -n "${host}" ] && [ -n "${active}" ]; then
        rust_lib_bin="${HOME}/.rustup/toolchains/${active}/lib/rustlib/${host}/bin"
        if [ -x "${rust_lib_bin}/llvm-readelf" ]; then
            readelf_bin="${rust_lib_bin}/llvm-readelf"
        elif [ -x "${rust_lib_bin}/llvm-readobj" ]; then
            readelf_bin="${rust_lib_bin}/llvm-readobj"
        fi
    fi
fi

if [ -n "${readelf_bin}" ]; then
    dyn_hits="$("${readelf_bin}" --dynamic "${bin}" 2>/dev/null | grep -cE 'DT_(NEEDED|RELA|HASH|SYMTAB|STRTAB|JMPREL|PLTREL|FLAGS_1|RELACOUNT)' || true)"
    if [ "${dyn_hits}" != "0" ]; then
        echo "::error::kernel ELF carries .dynamic entries; expected static link"
        "${readelf_bin}" --dynamic "${bin}" >&2
        exit 1
    fi
    echo "PASS: kernel ELF carries no .dynamic entries"

    rel_hits="$("${readelf_bin}" --relocations "${bin}" 2>/dev/null | grep -cE 'R_X86_64_|R_AARCH64_|R_RISCV_' || true)"
    if [ "${rel_hits}" != "0" ]; then
        echo "::error::kernel ELF carries relocations; expected static link"
        "${readelf_bin}" --relocations "${bin}" | head -20 >&2
        exit 1
    fi
    echo "PASS: kernel ELF carries no relocations"
else
    echo "[skip] readelf-class tool not found; cannot verify .dynamic / relocations are absent"
fi

echo "PASS: extended symbol scan clean for ${bin}"
