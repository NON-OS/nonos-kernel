#!/usr/bin/env bash
# Initialize a new Powers-of-Tau transcript (phase 1 start)
set -euo pipefail
POWER=""
OUT="pot_0000.ptau"
POWERSOFTAU="${POWERSOFTAU:-powersoftau}"
OPERATOR=""
LOGDIR="${LOGDIR:-ceremony_logs}"

usage() {
  cat <<EOF
init_powersoftau.sh --power <log2-degree> --operator "<Org:Name>" [--out <file>] [--tool <powersoftau>]
Creates initial PoT transcript and provenance JSON log. Intended for production ceremonies.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --power) POWER="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tool) POWERSOFTAU="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${POWER}" || -z "${OPERATOR}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }
command -v "${POWERSOFTAU}" >/dev/null 2>&1 || { echo "powersoftau not found; build with Dockerfile or place binary in PATH"; exit 1; }

mkdir -p "${LOGDIR}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOGFILE="${LOGDIR}/init_$(echo "${OPERATOR}" | tr ' /' '_')_${TIMESTAMP}.json"

echo "[init] Creating initial PoT with power=${POWER} using ${POWERSOFTAU}"
"${POWERSOFTAU}" new --power "${POWER}" --output "${OUT}"

SHA256=$(sha256sum "${OUT}" | awk '{print $1}')
TOOL_VER=$("${POWERSOFTAU}" --version 2>/dev/null || echo "unknown")
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
UNAME=$(uname -a)

# store hashed host/uname (no raw PII by default)
HOST_HASH="$(echo -n "${HOSTNAME}" | sha256sum | awk '{print $1}')"
UNAME_HASH="$(echo -n "${UNAME}" | sha256sum | awk '{print $1}')"

jq -n --arg artifact "$(basename "${OUT}")" \
      --arg path "$(realpath "${OUT}")" \
      --arg sha256 "${SHA256}" \
      --arg power "${POWER}" \
      --arg operator "${OPERATOR}" \
      --arg tool "${POWERSOFTAU}" \
      --arg tool_version "${TOOL_VER}" \
      --arg created_at "${TIMESTAMP}" \
      --arg host_hash "${HOST_HASH}" \
      --arg uname_hash "${UNAME_HASH}" \
      '{
        artifact: $artifact,
        path: $path,
        sha256: $sha256,
        power: $power,
        operator: $operator,
        tool: $tool,
        tool_version: $tool_version,
        created_at: $created_at,
        host_fingerprint: $host_hash,
        uname_fingerprint: $uname_hash
      }' > "${LOGFILE}"

echo "[init] Transcript created: ${OUT}"
echo "[init] Metadata written: ${LOGFILE}"
echo "transcript_sha256=${SHA256}"
echo "Distribute ${OUT} and ${LOGFILE} to participants securely."
