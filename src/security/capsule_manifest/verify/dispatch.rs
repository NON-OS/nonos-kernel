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

use crate::crypto::asymmetric::alg_id::{verify as alg_verify, AlgId};
use crate::security::nonos_id_cert::NonosIdCertificate;
use crate::security::nonos_trust_anchor::NonosTrustAnchorPolicy;

use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn run(
    alg: AlgId,
    manifest: &CapsuleManifest,
    cert: &NonosIdCertificate,
    policy: &NonosTrustAnchorPolicy,
    signed_region: &[u8],
) -> Result<(), ManifestVerifyError> {
    let mut last_err = ManifestVerifyError::PublisherPolicy;
    for sig in manifest.publisher_signatures.iter().filter(|s| s.algorithm == alg) {
        if policy.publisher_key_id_revoked(&sig.key_id) {
            last_err = ManifestVerifyError::PublisherKeyRevoked;
            continue;
        }
        let key = match cert.publisher_key_by_id(&sig.key_id) {
            Some(k) => k,
            None => {
                last_err = ManifestVerifyError::PublisherPolicy;
                continue;
            }
        };
        if key.algorithm != alg {
            continue;
        }
        match alg_verify(alg, key.pubkey_bytes(), signed_region, sig.sig_bytes()) {
            Ok(true) => return Ok(()),
            Ok(false) => last_err = ManifestVerifyError::PublisherBadSig(alg),
            Err(_) => last_err = ManifestVerifyError::PublisherBadSig(alg),
        }
    }
    Err(last_err)
}
