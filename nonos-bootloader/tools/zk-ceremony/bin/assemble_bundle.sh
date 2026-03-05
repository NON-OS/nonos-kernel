#!/usr/bin/env bash
# Assemble final bundle from per-signer signatures and signers.json (t-of-n)
set -euo pipefail

VK=""
META=""
SIGNERS_JSON=""
SIGS_DIR=""
OUT="attestation_bundle.tar.gz"
ARWEAVE_KEY=""
ALLOW_UNSIGNED=false

usage() {
  cat <<EOF
assemble_bundle.sh --vk <vk.bin> --meta <metadata.json> --signers <signers.json> --sigs-dir <dir> [--out <bundle>] [--arweave-key <path>] [--allow-unsigned]
Assembles a t-of-n signed bundle from per-signer signatures. Verifies threshold presence and optionally does basic signature verification.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vk) VK="$2"; shift 2 ;;
    --meta) META="$2"; shift 2 ;;
    --signers) SIGNERS_JSON="$2"; shift 2 ;;
    --sigs-dir) SIGS_DIR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --arweave-key) ARWEAVE_KEY="$2"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; shift 1 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${VK}" || -z "${META}" || -z "${SIGNERS_JSON}" || -z "${SIGS_DIR}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

TMPDIR=$(mktemp -d)
cp "${VK}" "${TMPDIR}/attestation_verifying_key.bin"
cp "${META}" "${TMPDIR}/metadata.json"
cp "${SIGNERS_JSON}" "${TMPDIR}/signers.json"

SIGNED_INPUT="${TMPDIR}/signed_input.bin"
cat "${TMPDIR}/attestation_verifying_key.bin" "${TMPDIR}/metadata.json" > "${SIGNED_INPUT}"

THRESHOLD=$(jq -r '.threshold // 0' "${SIGNERS_JSON}")
if [[ -z "${THRESHOLD}" || "${THRESHOLD}" == "0" ]]; then
  echo "signers.json missing or zero threshold" >&2
  rm -rf "${TMPDIR}"; exit 1
fi

mkdir -p "${TMPDIR}/signatures"
present=0
valid=0

for id in $(jq -r '.signers[].id' "${SIGNERS_JSON}"); do
  src="${SIGS_DIR}/${id}.sig"
  if [[ -f "${src}" ]]; then
    cp "${src}" "${TMPDIR}/signatures/${id}.sig"
    present=$((present+1))
  fi
done

echo "Signatures present: ${present}, required threshold: ${THRESHOLD}"
if [[ "${present}" -lt "${THRESHOLD}" ]]; then
  if [[ "${ALLOW_UNSIGNED}" == "true" ]]; then
    echo "Threshold not met but --allow-unsigned set: proceeding (NOT FOR PRODUCTION)"
  else
    echo "Threshold not met: aborting"
    rm -rf "${TMPDIR}"
    exit 2
  fi
fi

# Verification with ed25519verify (if available)
if command -v ./target/release/ed25519verify >/dev/null 2>&1; then
  for id in $(jq -r '.signers[].id' "${SIGNERS_JSON}"); do
    sigf="${TMPDIR}/signatures/${id}.sig"
    if [[ -f "${sigf}" ]]; then
      PUBHEX=$(jq -r --arg id "${id}" '.signers[] | select(.id==$id) | .pubkey_hex' "${SIGNERS_JSON}")
      if [[ -z "${PUBHEX}" || "${PUBHEX}" == "null" ]]; then
        echo "no pubkey for signer ${id} in signers.json"
        continue
      fi
      PUBBIN="${TMPDIR}/pub_${id}.bin"
      echo "${PUBHEX}" | xxd -r -p > "${PUBBIN}"
      if ./target/release/ed25519verify --pub "${PUBBIN}" --in "${SIGNED_INPUT}" --sig "${sigf}" >/dev/null 2>&1; then
        echo "signature ok: ${id}"
        valid=$((valid+1))
      else
        echo "signature INVALID: ${id}"
      fi
    fi
  done
  echo "valid signatures: ${valid}"
  if [[ "${valid}" -lt "${THRESHOLD}" ]]; then
    if [[ "${ALLOW_UNSIGNED}" == "true" ]]; then
      echo "valid signature count below threshold but --allow-unsigned set: continuing"
    else
      echo "valid signature count below threshold: aborting"
      rm -rf "${TMPDIR}"
      exit 3
    fi
  fi
else
  echo "ed25519verify not available: skipping local signature verification (CI must verify)"
fi

tar -C "${TMPDIR}" -czf "${OUT}" attestation_verifying_key.bin metadata.json signers.json signatures || { echo "tar failed"; rm -rf "${TMPDIR}"; exit 4; }
echo "bundle created: ${OUT} (sha256: $(sha256sum "${OUT}" | awk '{print $1}'))"

if [[ -n "${ARWEAVE_KEY}" ]]; then
  if command -v arweave >/dev/null 2>&1; then
    TXID=$(arweave deploy "${OUT}" --key-file "${ARWEAVE_KEY}" --yes 2>/dev/null | tail -n1)
    echo "Arweave txid: ${TXID}"
    echo "{\"arweave_txid\":\"${TXID}\"}" > "${TMPDIR}/arweave.json"
    tmp2="${OUT}.with_arweave.tar.gz"
    tar -C "${TMPDIR}" -czf "${tmp2}" attestation_verifying_key.bin metadata.json signers.json signatures arweave.json
    mv "${tmp2}" "${OUT}"
    echo "bundle repackaged with arweave.json; new sha256: $(sha256sum "${OUT}" | awk '{print $1}')"
  else
    echo "arweave CLI not found; skipping Arweave upload"
  fi
fi

echo "tmpdir preserved at ${TMPDIR} for audit. Remove when done."
