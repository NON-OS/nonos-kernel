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
use crate::verify::decoded::{DecodedCert, DecodedTaPolicy};

pub fn verify_cert(
    cert: &DecodedCert,
    cert_bytes: &[u8],
    policy: &DecodedTaPolicy,
    required_algs: &[AlgId],
    now_ms: Option<u64>,
) -> Result<(), SignError> {
    if cert.trust_anchor_epoch < policy.epoch {
        return Err(SignError::VerifyEpochStale);
    }
    if policy.revoked_cert_serials.iter().any(|s| *s == cert.cert_serial) {
        return Err(SignError::VerifyCertRevoked);
    }
    if policy.revoked_nonos_ids.iter().any(|id| id == &cert.nonos_id) {
        return Err(SignError::VerifyNonosIdRevoked);
    }
    if let Some(ts) = now_ms {
        if ts < cert.valid_from_ms {
            return Err(SignError::VerifyNotYetValid);
        }
        if ts >= cert.valid_until_ms {
            return Err(SignError::VerifyExpired);
        }
    }
    let signed_region = &cert_bytes[..cert.signed_region_len];
    for alg in required_algs.iter().copied() {
        verify_alg(alg, cert, signed_region, policy)?;
    }
    Ok(())
}

fn verify_alg(
    alg: AlgId,
    cert: &DecodedCert,
    signed_region: &[u8],
    policy: &DecodedTaPolicy,
) -> Result<(), SignError> {
    let sig = cert
        .trust_anchor_signatures
        .iter()
        .find(|s| s.alg == alg)
        .ok_or(SignError::VerifyTrustAnchorPolicy)?;
    for key in policy.keys.iter().filter(|k| k.alg == alg) {
        if let Ok(true) = verify_with(alg, &key.pubkey, signed_region, &sig.sig) {
            return Ok(());
        }
    }
    Err(SignError::VerifyTrustAnchorBadSig(alg.label()))
}
