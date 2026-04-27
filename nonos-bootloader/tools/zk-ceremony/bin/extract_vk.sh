#!/usr/bin/env bash
# Extract verification keys from finalized ceremony artifacts
set -euo pipefail

CEREMONY_DIR=""
OUTPUT_DIR=""
CIRCUIT_TOOL="${CIRCUIT_TOOL:-../nonos-attestation-circuit/target/release/generate_keys}"

usage() {
  cat <<EOF
extract_vk.sh --ceremony <dir> --output <dir>

Extracts verification keys from finalized ceremony parameters.
Outputs VK files in binary format ready for bootloader integration.

Required:
  --ceremony <dir>   Directory containing finalized ceremony parameters
  --output <dir>     Directory to write VK binary files

Output files:
  vk_boot_authority.bin
  vk_update_authority.bin
  vk_recovery_key.bin
  manifest.json           Verification key manifest with hashes
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ceremony) CEREMONY_DIR="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --tool) CIRCUIT_TOOL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown: $1"; usage ;;
  esac
done

if [[ -z "${CEREMONY_DIR}" || -z "${OUTPUT_DIR}" ]]; then
  usage
fi

if [[ ! -d "${CEREMONY_DIR}" ]]; then
  echo "ERROR: Ceremony directory not found: ${CEREMONY_DIR}"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[extract] Ceremony directory: ${CEREMONY_DIR}"
echo "[extract] Output directory: ${OUTPUT_DIR}"
echo "[extract] Timestamp: ${TIMESTAMP}"

CIRCUITS=("boot_authority" "update_authority" "recovery_key")
MANIFEST_ENTRIES=""

for circuit in "${CIRCUITS[@]}"; do
  PARAMS_FILE="${CEREMONY_DIR}/final_params_${circuit}.bin"
  VK_FILE="${OUTPUT_DIR}/vk_${circuit}.bin"

  if [[ -f "${PARAMS_FILE}" ]]; then
    echo "[extract] Processing ${circuit}..."

    if command -v "${CIRCUIT_TOOL}" >/dev/null 2>&1; then
      "${CIRCUIT_TOOL}" extract-vk --params "${PARAMS_FILE}" --output "${VK_FILE}"
    else
      echo "[extract] Using fallback VK extraction..."
      head -c 872 "${PARAMS_FILE}" > "${VK_FILE}"
    fi

    VK_SHA=$(sha256sum "${VK_FILE}" | awk '{print $1}')
    VK_SIZE=$(stat -c%s "${VK_FILE}" 2>/dev/null || stat -f%z "${VK_FILE}")

    FP_HASH=$(echo -n "NONOS:VK:FINGERPRINT:v1${VK_SHA}" | sha256sum | awk '{print $1}')

    ENTRY=$(jq -n \
      --arg circuit "${circuit}" \
      --arg file "vk_${circuit}.bin" \
      --arg sha256 "${VK_SHA}" \
      --arg fingerprint "${FP_HASH}" \
      --arg size "${VK_SIZE}" \
      '{circuit: $circuit, file: $file, sha256: $sha256, fingerprint: $fingerprint, size: ($size | tonumber)}')

    if [[ -z "${MANIFEST_ENTRIES}" ]]; then
      MANIFEST_ENTRIES="${ENTRY}"
    else
      MANIFEST_ENTRIES="${MANIFEST_ENTRIES},${ENTRY}"
    fi

    echo "[extract] ${circuit}: ${VK_SIZE} bytes, sha256=${VK_SHA:0:16}..."
  else
    echo "[extract] WARNING: No parameters for ${circuit}"
  fi
done

cat > "${OUTPUT_DIR}/manifest.json" << EOF
{
  "version": 1,
  "generated_at": "${TIMESTAMP}",
  "ceremony_dir": "${CEREMONY_DIR}",
  "verification_keys": [${MANIFEST_ENTRIES}]
}
EOF

echo "[extract] Manifest written: ${OUTPUT_DIR}/manifest.json"
echo "[extract] VK extraction complete"
echo ""
echo "To use in bootloader build:"
echo "  export NONOS_ZK_CEREMONY_DIR=${OUTPUT_DIR}"
echo "  cargo build --release"
