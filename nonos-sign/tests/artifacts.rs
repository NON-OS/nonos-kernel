// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::verify::decode::{
    decode_cert, decode_manifest, decode_trust_anchor_policy,
};
use nonos_capsule_sign::verify::{verify_cert, verify_manifest};

const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];
// Inside the cert validity window declared in the Makefile
// (2026-01-01 .. 2030-01-01).
const NOW_MS: u64 = 1_778_025_600_000;

// Committed artifacts live under nonos-data/trust/. nonos-sign
// runs from the nonos-sign/ directory under `cargo test`, so all
// paths are anchored at the parent (`..`).
const POLICY_PATH: &str = "../nonos-data/trust/policy/nonos_trust_anchor.policy.bin";

struct Artifacts {
    name: &'static str,
    bin_name: &'static str,
}

const VERIFIED: &[Artifacts] = &[
    Artifacts { name: "proof_io",            bin_name: "proof_io" },
    Artifacts { name: "ramfs",               bin_name: "ramfs" },
    Artifacts { name: "keyring",             bin_name: "keyring" },
    Artifacts { name: "entropy",             bin_name: "entropy" },
    Artifacts { name: "crypto",              bin_name: "crypto" },
    Artifacts { name: "vfs",                 bin_name: "vfs" },
    Artifacts { name: "market",              bin_name: "market" },
    Artifacts { name: "driver.virtio_rng",   bin_name: "driver_virtio_rng" },
    Artifacts { name: "driver.ps2_kbd0",     bin_name: "driver_ps2_input" },
    Artifacts { name: "driver.virtio_blk0",  bin_name: "driver_virtio_blk" },
    Artifacts { name: "driver.virtio_net0",  bin_name: "driver_virtio_net" },
    Artifacts { name: "driver.xhci0",        bin_name: "driver_xhci" },
    Artifacts { name: "driver.e1000_0",      bin_name: "driver_e1000" },
];

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("missing artifact {path}: {e}"))
}

fn cert_path(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.nonos_id_cert.bin")
}

fn manifest_path(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.manifest.bin")
}

fn stale_marker(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.STALE")
}

#[test]
fn on_disk_artifacts_verify_against_baked_policy() {
    let policy_bytes = read(POLICY_PATH);
    let policy = decode_trust_anchor_policy(&policy_bytes)
        .expect("baked trust-anchor policy must decode");

    for a in VERIFIED {
        let cert_p = cert_path(a.bin_name);
        let manifest_p = manifest_path(a.bin_name);
        let stale_p = stale_marker(a.bin_name);

        if std::path::Path::new(&stale_p).exists() {
            // Capsule's committed artifacts are documented as out
            // of date; cryptographic verification is suspended
            // until a fresh re-sign lands. Decoding alone is still
            // enforced — a corrupt blob is never excused.
            let cert_bytes = read(&cert_p);
            decode_cert(&cert_bytes).unwrap_or_else(|e| {
                panic!("{}: STALE marker present but cert still must decode: {:?}", a.name, e)
            });
            let manifest_bytes = read(&manifest_p);
            decode_manifest(&manifest_bytes).unwrap_or_else(|e| {
                panic!("{}: STALE marker present but manifest still must decode: {:?}", a.name, e)
            });
            eprintln!(
                "STALE: {} — committed cert + manifest decoded; cryptographic binding skipped per {}",
                a.name, stale_p
            );
            continue;
        }

        let cert_bytes = read(&cert_p);
        let manifest_bytes = read(&manifest_p);

        let cert = decode_cert(&cert_bytes)
            .unwrap_or_else(|e| panic!("{}: cert decode failed: {:?}", a.name, e));
        verify_cert(&cert, &cert_bytes, &policy, REQUIRED_ALGS, Some(NOW_MS))
            .unwrap_or_else(|e| panic!("{}: cert verify failed: {:?}", a.name, e));

        let manifest = decode_manifest(&manifest_bytes)
            .unwrap_or_else(|e| panic!("{}: manifest decode failed: {:?}", a.name, e));
        verify_manifest(
            &manifest,
            &manifest_bytes,
            &cert,
            &cert_bytes,
            &policy,
            REQUIRED_ALGS,
        )
        .unwrap_or_else(|e| panic!("{}: manifest verify failed: {:?}", a.name, e));
    }
}
