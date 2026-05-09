#!/usr/bin/env bash
# Compare an actual count against a baseline file.
# Usage: check-baseline.sh <label> <baseline-file> <actual-count>
# Exits 0 if actual <= baseline, 1 otherwise. Always prints both.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <label> <baseline-file> <actual-count>" >&2
    exit 2
fi

label="$1"
baseline_file="$2"
actual="$3"

if [ ! -f "${baseline_file}" ]; then
    echo "::error::baseline file missing: ${baseline_file}" >&2
    exit 1
fi

expected="$(tr -d '[:space:]' < "${baseline_file}")"
case "${expected}" in
    ''|*[!0-9]*)
        echo "::error::baseline ${baseline_file} is not an integer: '${expected}'" >&2
        exit 1
        ;;
esac

case "${actual}" in
    ''|*[!0-9]*)
        echo "::error::actual count for '${label}' is not an integer: '${actual}'" >&2
        exit 1
        ;;
esac

echo "[${label}] baseline=${expected} actual=${actual}"

if [ "${actual}" -gt "${expected}" ]; then
    echo "::error::baseline exceeded for '${label}': baseline=${expected} actual=${actual}" >&2
    echo "if intentional, update ${baseline_file} in this PR" >&2
    exit 1
fi
