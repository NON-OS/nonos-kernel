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

use crate::crypto::util::constant_time::ct_eq_32;

use super::error::MultiSigError;
use super::material::{compute_signature, signature_material};
use super::token_type::MultiSigToken;

fn count_valid_sigs(token: &MultiSigToken, keys: &[(&u64, &[u8; 32])]) -> (usize, Option<u64>) {
    let mut valid = 0;
    let mut bad_signer: Option<u64> = None;
    for (signer_id, sig) in &token.signatures {
        if let Some((_, key)) = keys.iter().find(|(id, _)| **id == *signer_id) {
            let expected = compute_signature(key, &signature_material(token, *signer_id));
            if ct_eq_32(sig, &expected) {
                valid += 1;
            } else if bad_signer.is_none() {
                bad_signer = Some(*signer_id);
            }
        }
    }
    (valid, bad_signer)
}

pub fn verify_multisig(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<bool, MultiSigError> {
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }
    Ok(count_valid_sigs(token, keys).0 >= token.threshold)
}

pub fn verify_multisig_strict(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<(), MultiSigError> {
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }
    let (valid, bad_sig) = count_valid_sigs(token, keys);
    if let Some(signer_id) = bad_sig {
        return Err(MultiSigError::InvalidSignature { signer_id });
    }
    if valid < token.threshold {
        return Err(MultiSigError::ThresholdNotMet { have: valid, need: token.threshold });
    }
    Ok(())
}

pub fn count_valid_signatures(token: &MultiSigToken, keys: &[(&u64, &[u8; 32])]) -> usize {
    let mut valid = 0;
    for (signer_id, sig) in &token.signatures {
        if let Some((_, key)) = keys.iter().find(|(id, _)| **id == *signer_id) {
            let expected = compute_signature(key, &signature_material(token, *signer_id));
            if ct_eq_32(sig, &expected) {
                valid += 1;
            }
        }
    }
    valid
}
