#!/usr/bin/env bash
# Contribute to a PoT transcript 
set -euo pipefail

IN=""
OUT=""
NAME=""
ENTROPY="/dev/random"
POWERSOFTAU="${POWERSOFTAU:-powersoftau}"
LOGDIR="${LOGDIR:-contrib_logs}"
LOCAL_SIGN_KEY=""
REDACT=true

usage() {
  cat <<EOF
contribute.sh --in <in.ptau> --out <out.ptau> --name "<Org:Name>" [--entropy <file>] [--tool <powersoftau>] [--local-sign-key <path>] [--no-redact]
Verifies prior transcript, contributes randomness, emits JSON log. PII is redacted by default.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in) IN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --entropy) ENTROPY="$2"; shift 2 ;;
    --tool) POWERSOFTAU="$2"; shift 2 ;;
    --local-sign-key) LOCAL_SIGN_KEY="$2"; shift 2 ;;
    --no-redact) REDACT=false; shift 1 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${IN}" || -z "${OUT}" || -z "${NAME}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v "${POWERSOFTAU}" >/dev/null 2>&1 || { echo "powersoftau binary not found"; exit 1; }

mkdir -p "${LOGDIR}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOGFILE="${LOGDIR}/contrib_$(echo "${NAME}" | tr ' /' '_')_${TIMESTAMP}.json"

echo "[contrib] Verifying prior transcript ${IN}"
"${POWERSOFTAU}" verify --input "${IN}" || { echo "prior transcript verification failed"; exit 2; }

echo "[contrib] Contributing randomness..."
"${POWERSOFTAU}" contribute --input "${IN}" --output "${OUT}" --name "${NAME}" --entropy "${ENTROPY}"

OUT_SHA=$(sha256sum "${OUT}" | awk '{print $1}')
IN_SHA=$(sha256sum "${IN}" | awk '{print $1}')
POW_VER=$("${POWERSOFTAU}" --version 2>/dev/null || echo "unknown")
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
UNAME=$(uname -a)

if [[ "${REDACT}" == "true" ]]; then
  HOST_FIELD="$(echo -n "${HOSTNAME}" | sha256sum | awk '{print $1}')"
  UNAME_FIELD="$(echo -n "${UNAME}" | sha256sum | awk '{print $1}')"
else
  HOST_FIELD="${HOSTNAME}"
  UNAME_FIELD="${UNAME}"
fi

jq -n --arg participant "${NAME}" \
      --arg input_transcript "$(basename "${IN}")" \
      --arg input_sha "${IN_SHA}" \
      --arg output_transcript "$(basename "${OUT}")" \
      --arg output_sha "${OUT_SHA}" \
      --arg powersoftau "${POWERSOFTAU}" \
      --arg powersoftau_version "${POW_VER}" \
      --arg entropy "${ENTROPY}" \
      --arg timestamp "${TIMESTAMP}" \
      --arg host_fingerprint "${HOST_FIELD}" \
      --arg uname_fingerprint "${UNAME_FIELD}" \
      '{
        participant: $participant,
        input_transcript: $input_transcript,
        input_sha256: $input_sha,
        output_transcript: $output_transcript,
        output_sha256: $output_sha,
        powersoftau: $powersoftau,
        powersoftau_version: $powersoftau_version,
        entropy_source: $entropy,
        timestamp: $timestamp,
        host_fingerprint: $host_fingerprint,
        uname_fingerprint: $uname_fingerprint
      }' > "${LOGFILE}"

echo "[contrib] Contribution log: ${LOGFILE}"

if [[ -n "${LOCAL_SIGN_KEY}" ]]; then
  if command -v ./target/release/ed25519sign >/dev/null 2>&1; then
    ./target/release/ed25519sign --key "${LOCAL_SIGN_KEY}" --in "${LOGFILE}" --out "${LOGFILE}.sig" || echo "[contrib] local signing failed"
    echo "[contrib] Signed log: ${LOGFILE}.sig"
  else
    echo "[contrib] ed25519sign not available; skip local signing. Use HSM for production."
  fi
fi

echo "contribution_complete=true"
echo "contribution_log=${LOGFILE}"
echo "Publish ${OUT} and ${LOGFILE} (and ${LOGFILE}.sig if produced) to artifact store."
