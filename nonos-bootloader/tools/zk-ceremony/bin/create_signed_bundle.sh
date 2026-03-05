#!/usr/bin/env bash
# Create a signed VK bundle. Delegates to assemble_bundle.sh for t-of-n flows (recommended).
set -euo pipefail

VK=""
META=""
OUT="attestation_bundle.tar.gz"
LOCAL_SIGN_KEY=""
SIGNERS_JSON=""
SIGS_DIR=""
ARWEAVE_KEY=""

usage() {
  cat <<EOF
create_signed_bundle.sh --vk <vk.bin> --metadata <metadata.json> --out <bundle> [--local-sign-key <path>] [--signers-json <path> --sigs-dir <dir>] [--arweave-key <path>]
If --signers-json and --sigs-dir provided, assemble a t-of-n bundle (recommended).
Single-signer local signing is provided for dev/test only.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vk) VK="$2"; shift 2 ;;
    --metadata) META="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --local-sign-key) LOCAL_SIGN_KEY="$2"; shift 2 ;;
    --signers-json) SIGNERS_JSON="$2"; shift 2 ;;
    --sigs-dir) SIGS_DIR="$2"; shift 2 ;;
    --arweave-key) ARWEAVE_KEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${VK}" || -z "${META}" ]]; then
  usage
fi

if [[ -n "${SIGNERS_JSON}" && -n "${SIGS_DIR}" ]]; then
  ./tools/zk-ceremony/bin/assemble_bundle.sh --vk "${VK}" --meta "${META}" --signers "${SIGNERS_JSON}" --sigs-dir "${SIGS_DIR}" --out "${OUT}" --arweave-key "${ARWEAVE_KEY}"
  exit 0
fi

# Single-signer fallback (dev/test only)
TMPDIR=$(mktemp -d)
cp "${VK}" "${TMPDIR}/attestation_verifying_key.bin"
cp "${META}" "${TMPDIR}/metadata.json"
SIGN_INPUT="${TMPDIR}/signed_input.bin"
cat "${TMPDIR}/attestation_verifying_key.bin" "${TMPDIR}/metadata.json" > "${SIGN_INPUT}"
SIG_OUT="${TMPDIR}/signature.sig"

if [[ -n "${LOCAL_SIGN_KEY}" ]]; then
  if command -v ./target/release/ed25519sign >/dev/null 2>&1; then
    ./target/release/ed25519sign --key "${LOCAL_SIGN_KEY}" --in "${SIGN_INPUT}" --out "${SIG_OUT}"
  else
    echo "ed25519sign not built; build tools/sign-tools before using local signing" >&2
    exit 1
  fi
else
  echo "[bundle] No signing method provided; producing unsigned bundle (NOT FOR PRODUCTION)"
  > "${SIG_OUT}"
fi

tar -C "${TMPDIR}" -czf "${OUT}" attestation_verifying_key.bin metadata.json signature.sig
echo "bundle created: ${OUT} (sha256: $(sha256sum "${OUT}" | awk '{print $1}'))"
if [[ -n "${ARWEAVE_KEY}" ]]; then
  if command -v arweave >/dev/null 2>&1; then
    TXID=$(arweave deploy "${OUT}" --key-file "${ARWEAVE_KEY}" --yes 2>/dev/null | tail -n1)
    echo "Arweave txid: ${TXID}"
  else
    echo "arweave CLI not found; skipping Arweave upload"
  fi
fi
