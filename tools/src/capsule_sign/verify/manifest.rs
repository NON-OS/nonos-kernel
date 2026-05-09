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

use crate::algs::AlgId;
use crate::error::SignError;
use crate::sign::verify_with;
use crate::verify::decoded::{DecodedCert, DecodedManifest, DecodedTaPolicy};
use crate::verify::glob::glob_match;

pub fn verify_manifest(
    manifest: &DecodedManifest,
    manifest_bytes: &[u8],
    cert: &DecodedCert,
    cert_bytes: &[u8],
    policy: &DecodedTaPolicy,
    required_algs: &[AlgId],
) -> Result<(), SignError> {
    let cert_id = *blake3::hash(cert_bytes).as_bytes();
    if cert_id != manifest.nonos_id_cert_id {
        return Err(SignError::VerifyNonosIdCertIdMismatch);
    }
    if !cert.namespace_globs.iter().any(|g| glob_match(g, &manifest.namespace)) {
        return Err(SignError::VerifyNamespaceOutsideCert);
    }
    let used = manifest.required_caps | manifest.optional_caps;
    if used & !cert.allowed_caps_ceiling != 0 {
        return Err(SignError::VerifyCapsExceedCeiling);
    }
    let signed_region = &manifest_bytes[..manifest.signed_region_len];
    for alg in required_algs.iter().copied() {
        verify_alg(alg, manifest, signed_region, cert, policy)?;
    }
    Ok(())
}

fn verify_alg(
    alg: AlgId,
    manifest: &DecodedManifest,
    signed_region: &[u8],
    cert: &DecodedCert,
    policy: &DecodedTaPolicy,
) -> Result<(), SignError> {
    let mut last_err = SignError::VerifyPublisherPolicy;
    for sig in manifest.publisher_signatures.iter().filter(|s| s.alg == alg) {
        if policy.revoked_publisher_key_ids.iter().any(|k| k == &sig.key_id) {
            last_err = SignError::VerifyPublisherKeyRevoked;
            continue;
        }
        let key = match cert.publisher_keys.iter().find(|k| k.key_id == sig.key_id) {
            Some(k) => k,
            None => {
                last_err = SignError::VerifyPublisherPolicy;
                continue;
            }
        };
        if key.alg != alg {
            continue;
        }
        match verify_with(alg, &key.pubkey, signed_region, &sig.sig) {
            Ok(true) => return Ok(()),
            _ => last_err = SignError::VerifyPublisherBadSig(alg.label()),
        }
    }
    Err(last_err)
}
