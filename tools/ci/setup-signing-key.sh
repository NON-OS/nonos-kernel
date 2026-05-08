#!/usr/bin/env bash
# Resolve a 32-byte Ed25519 dev-signing seed for a CI lane.
#
# Upstream `main` on `NON-OS/nonos-micro-kernel` carries the production
# `SIGNING_KEY_BASE64` secret; that key is what we use for every
# image whose hash is recorded in the production-ledger.
#
# Forks (e.g. `eKisNonos/nonos-micro-kernel`) do not have access to that
# secret. Without a fallback every fork CI run goes red on the
# first build step. To keep the contract honest the fallback is
# narrow: a deterministic 32-byte string, marked plainly as a fork
# dev seed. The resulting kernel image is signature-shaped but does
# not chain to the upstream signing key — anything the
# production-ledger trusts must be re-signed by the upstream lane.

set -euo pipefail

mkdir -p .keys

if [ -n "${SIGNING_KEY_BASE64:-}" ]; then
    printf '%s' "${SIGNING_KEY_BASE64}" | base64 -d > .keys/dev-signing.seed
else
    echo "::warning::SIGNING_KEY_BASE64 not set; using deterministic fork dev seed"
    printf 'NONOS-CI-FORK-DEV-SEED-32-BYTE!!' > .keys/dev-signing.seed
fi

chmod 600 .keys/dev-signing.seed

if [ "$(wc -c < .keys/dev-signing.seed)" -ne 32 ]; then
    echo "::error::signing key must be 32 bytes"
    exit 1
fi
