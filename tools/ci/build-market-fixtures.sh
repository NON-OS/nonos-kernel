#!/usr/bin/env bash
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Build the four fixture blobs the marketplace boot smoke
# embeds. The trusted seed is `0x42`-repeated-32 (publicly known,
# documented as such in the userland bootstrap-trust list under
# the `smoketest-trust` feature). The untrusted seed is
# `0xAA`-repeated-32; that pubkey is never added to the trust
# list, so its blobs must be refused by capsule_market.

set -euo pipefail

OUT_DIR="${1:?out dir}"
TOOL="${2:?marketplace-index path}"

mkdir -p "${OUT_DIR}"

# Deterministic seeds. printf interprets \xNN escapes.
printf '\x42%.0s' {1..32} > "${OUT_DIR}/seed-trusted"
printf '\xaa%.0s' {1..32} > "${OUT_DIR}/seed-untrusted"
chmod 0600 "${OUT_DIR}/seed-trusted" "${OUT_DIR}/seed-untrusted"

# Trusted pubkey (matches the SMOKETEST_OPERATOR constant in
# userland/capsule_market/src/bootstrap_trust/keys.rs).
TRUSTED_PUB="2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"

# Empty signed index, serial=1.
cat > "${OUT_DIR}/empty.json" <<'JSON'
{
  "schema_version": 1,
  "operator_id": "smoketest.marketplace.v1",
  "published_at_ms": 1700000000000,
  "serial": 1,
  "entries": []
}
JSON
"${TOOL}" sign \
    --in "${OUT_DIR}/empty.json" \
    --key-file "${OUT_DIR}/seed-trusted" \
    --pubkey "${TRUSTED_PUB}" \
    --out "${OUT_DIR}/empty.bin" >/dev/null

# Preview entry, serial=2. Keeps install_ready=false: package_url
# blank, validation pending, publisher_signature absent.
cat > "${OUT_DIR}/preview.json" <<'JSON'
{
  "schema_version": 1,
  "operator_id": "smoketest.marketplace.v1",
  "published_at_ms": 1700000001000,
  "serial": 2,
  "entries": [
    {
      "listing_id": "preview.demo.v1",
      "capsule_id": "0000000000000000000000000000000000000000000000000000000000000000",
      "name": "Smoketest Preview",
      "publisher_name": "NONOS Smoketest",
      "publisher_pubkey": "0000000000000000000000000000000000000000000000000000000000000000",
      "description": "Preview-only fixture; not installable.",
      "price": { "kind": "free", "amount_atomic": "0", "period_seconds": 0 },
      "token": { "symbol": "NOX", "decimals": 18, "chain_id": 1, "contract_address": "" },
      "releases": [
        {
          "release_id": "preview-0",
          "manifest_hash": "0000000000000000000000000000000000000000000000000000000000000000",
          "package_hash": "0000000000000000000000000000000000000000000000000000000000000000",
          "package_url": "",
          "publisher_signature": "",
          "supported_arches": ["x86_64-nonos"],
          "kernel_abi_min": 1,
          "required_capabilities": [],
          "validation": {
            "status": "pending",
            "note": "smoke fixture",
            "validator_id": "smoketest",
            "validated_at_ms": 0
          }
        }
      ]
    }
  ]
}
JSON
"${TOOL}" sign \
    --in "${OUT_DIR}/preview.json" \
    --key-file "${OUT_DIR}/seed-trusted" \
    --pubkey "${TRUSTED_PUB}" \
    --out "${OUT_DIR}/preview.bin" >/dev/null

# Mutated body: flip a byte inside `serial` so the operator pubkey
# crosscheck still passes and the signature-verify branch fires.
# Layout: u32 schema_version | u32 op_id_len | op_id | 32 pubkey
# | u64 published_at_ms | u64 serial. With operator_id length 24
# the serial starts at offset 4+4+24+32+8 = 72. Flipping byte 75
# perturbs the serial without touching the embedded pubkey.
cp "${OUT_DIR}/empty.bin" "${OUT_DIR}/mutated.bin"
printf '\xff' | dd of="${OUT_DIR}/mutated.bin" bs=1 seek=75 count=1 conv=notrunc 2>/dev/null

# Untrusted operator: same JSON shape, signed with the untrusted
# seed. Bootstrap-trust will refuse it because its pubkey is not
# in the trust list.
"${TOOL}" sign \
    --in "${OUT_DIR}/empty.json" \
    --key-file "${OUT_DIR}/seed-untrusted" \
    --out "${OUT_DIR}/untrusted.bin" >/dev/null

# Drop the seed files now that signing is done. The fixture blobs
# stay; the seed material does not need to live alongside them.
rm -f "${OUT_DIR}/seed-trusted" "${OUT_DIR}/seed-untrusted"

echo "wrote ${OUT_DIR}/{empty,preview,mutated,untrusted}.bin"
