#!/usr/bin/env bash
# Prepare a phase-2 file for circuit-specific setup using the final tau.
set -euo pipefail

TAU=""
OUT=""
POWERSOFTAU="${POWERSOFTAU:-powersoftau}"

usage() {
  cat <<EOF
prepare_phase2.sh --tau <final.ptau> --out <phase2.ptau> [--tool <powersoftau>]
Produces a phase2 transcript ready for circuit-specific Groth16 setup.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tau) TAU="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tool) POWERSOFTAU="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${TAU}" || -z "${OUT}" ]]; then
  usage
fi

command -v "${POWERSOFTAU}" >/dev/null 2>&1 || { echo "powersoftau binary not found"; exit 1; }

echo "[prepare_phase2] TAU=${TAU}, OUT=${OUT}, tool=${POWERSOFTAU}"
"${POWERSOFTAU}" prepare_phase2 --input "${TAU}" --output "${OUT}" || { echo "prepare_phase2 failed"; exit 2; }
echo "phase2 prepared -> ${OUT} (sha256: $(sha256sum ${OUT} | awk '{print $1}'))"
