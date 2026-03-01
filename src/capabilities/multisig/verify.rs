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

use super::error::MultiSigError;
use super::material::{compute_signature, signature_material};
use super::token::MultiSigToken;

pub fn verify_multisig(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<bool, MultiSigError> {
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    let mut valid_count = 0;

    for (signer_id, sig) in &token.signatures {
        let key = keys.iter().find(|(id, _)| **id == *signer_id);

        if let Some((_, key)) = key {
            let mat = signature_material(token, *signer_id);
            let expected = compute_signature(key, &mat);

            if *sig == expected {
                valid_count += 1;
            }
        }
    }

    Ok(valid_count >= token.threshold)
}

pub fn verify_multisig_strict(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<(), MultiSigError> {
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    let mut valid_count = 0;

    for (signer_id, sig) in &token.signatures {
        let key = keys.iter().find(|(id, _)| **id == *signer_id);

        if let Some((_, key)) = key {
            let mat = signature_material(token, *signer_id);
            let expected = compute_signature(key, &mat);

            if *sig == expected {
                valid_count += 1;
            } else {
                return Err(MultiSigError::InvalidSignature {
                    signer_id: *signer_id,
                });
            }
        }
    }

    if valid_count < token.threshold {
        return Err(MultiSigError::ThresholdNotMet {
            have: valid_count,
            need: token.threshold,
        });
    }

    Ok(())
}

pub fn count_valid_signatures(token: &MultiSigToken, keys: &[(&u64, &[u8; 32])]) -> usize {
    let mut valid_count = 0;

    for (signer_id, sig) in &token.signatures {
        let key = keys.iter().find(|(id, _)| **id == *signer_id);

        if let Some((_, key)) = key {
            let mat = signature_material(token, *signer_id);
            let expected = compute_signature(key, &mat);

            if *sig == expected {
                valid_count += 1;
            }
        }
    }

    valid_count
}
