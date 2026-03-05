#!/usr/bin/env bash
# Inspect a signed VK bundle and verify t-of-n signatures (if present).
set -euo pipefail

BUNDLE=""
REQUIRE_THRESHOLD=false

usage() {
  cat <<EOF
inspect_bundle.sh --bundle <bundle.tar.gz> [--require-threshold]
Inspect bundle contents, print metadata, compute vk_blake3 and verify signatures according to signers.json.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --require-threshold) REQUIRE_THRESHOLD=true; shift 1 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${BUNDLE}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }

TMP=$(mktemp -d)
tar -xzf "${BUNDLE}" -C "${TMP}"
VK="${TMP}/attestation_verifying_key.bin"
META="${TMP}/metadata.json"
SIGNERS_JSON="${TMP}/signers.json"

echo "[inspect] metadata:"
if [[ -f "${META}" ]]; then
  cat "${META}" | jq -C .
else
  echo "metadata.json missing"
fi

if command -v blake3 >/dev/null 2>&1; then
  VK_BLAKE3=$(blake3 "${VK}")
else
  if command -v python3 >/dev/null 2>&1; then
    VK_BLAKE3=$(python3 - <<PY
import blake3
b=open("${VK}","rb").read()
print(blake3.blake3(b).hexdigest())
PY
)
  else
    VK_BLAKE3="blake3-tool-missing"
  fi
fi
echo "[inspect] vk_blake3: ${VK_BLAKE3}"
if [[ -f "${META}" ]]; then
  echo "[inspect] metadata vk_blake3: $(jq -r '.vk_blake3 // "none"' ${META})"
fi

if [[ -f "${SIGNERS_JSON}" ]]; then
  THRESHOLD=$(jq -r '.threshold' "${SIGNERS_JSON}")
  echo "[inspect] signers.json present, threshold: ${THRESHOLD}"
  VALID=0
  for id in $(jq -r '.signers[].id' "${SIGNERS_JSON}"); do
    SIGF="${TMP}/signatures/${id}.sig"
    if [[ -f "${SIGF}" ]]; then
      PUBHEX=$(jq -r --arg id "${id}" '.signers[] | select(.id==$id) | .pubkey_hex' "${SIGNERS_JSON}")
      PUBBIN="${TMP}/pub_${id}.bin"
      echo "${PUBHEX}" | xxd -r -p > "${PUBBIN}"
      if command -v ./target/release/ed25519verify >/dev/null 2>&1; then
        if ./target/release/ed25519verify --pub "${PUBBIN}" --in "${VK}" --sig "${SIGF}" >/dev/null 2>&1; then
          echo " - ${id}: OK"
          VALID=$((VALID+1))
        else
          echo " - ${id}: INVALID"
        fi
      else
        echo " - ${id}: signature present (verification tool missing)"
      fi
    else
      echo " - ${id}: signature missing"
    fi
  done
  echo "[inspect] valid signatures: ${VALID}"
  if [[ "${VALID}" -lt "${THRESHOLD}" ]]; then
    if [[ "${REQUIRE_THRESHOLD}" == "true" ]]; then
      echo "Threshold not met: failing"
      exit 4
    else
      echo "Threshold not met (use --require-threshold to fail)"
    fi
  fi
else
  echo "[inspect] signers.json not present; unsigned bundle"
  if [[ "${REQUIRE_THRESHOLD}" == "true" ]]; then
    echo "Threshold required but missing: failing"
    exit 5
  fi
fi

echo "[inspect] done. tmpdir: ${TMP}"
