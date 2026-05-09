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

use crate::error::SignError;
use crate::wire::constants::{
    MAX_REVOKED_CERT_SERIALS, MAX_REVOKED_NONOS_IDS, MAX_REVOKED_PUBLISHER_KEY_IDS,
    MAX_TRUST_ANCHOR_KEYS,
};

use super::inputs::{TrustAnchorKeyInput, TrustAnchorPolicyInput};

pub(super) fn check(input: &TrustAnchorPolicyInput) -> Result<(), SignError> {
    if input.keys.is_empty() || input.keys.len() > MAX_TRUST_ANCHOR_KEYS {
        return Err(SignError::TaKeyCount(input.keys.len()));
    }
    for k in &input.keys {
        check_key(k)?;
    }
    if input.revoked_cert_serials.len() > MAX_REVOKED_CERT_SERIALS {
        return Err(SignError::TaRevokedCertSerialCount(input.revoked_cert_serials.len()));
    }
    if input.revoked_nonos_ids.len() > MAX_REVOKED_NONOS_IDS {
        return Err(SignError::TaRevokedNonosIdCount(input.revoked_nonos_ids.len()));
    }
    if input.revoked_publisher_key_ids.len() > MAX_REVOKED_PUBLISHER_KEY_IDS {
        return Err(SignError::TaRevokedPublisherKeyIdCount(input.revoked_publisher_key_ids.len()));
    }
    Ok(())
}

fn check_key(k: &TrustAnchorKeyInput) -> Result<(), SignError> {
    if k.pubkey.len() != k.alg.pubkey_len() {
        return Err(SignError::TaPubkeyLen { alg: k.alg.label(), expected: k.alg.pubkey_len(), got: k.pubkey.len() });
    }
    if k.valid_from_ms == 0 {
        return Err(SignError::TaValidFromZero);
    }
    if k.valid_until_ms != 0 && k.valid_until_ms <= k.valid_from_ms {
        return Err(SignError::TaValidWindow { from: k.valid_from_ms, until: k.valid_until_ms });
    }
    Ok(())
}
