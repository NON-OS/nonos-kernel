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

extern crate alloc;

use crate::capabilities::token::default_nonce;
use crate::capabilities::types::Capability;
use alloc::vec::Vec;

use super::constants::MAX_SIGNERS;
use super::error::MultiSigError;
use super::token_type::MultiSigToken;

fn validate_params(threshold: usize, signers: &[u64]) -> Result<(), MultiSigError> {
    if threshold == 0 {
        return Err(MultiSigError::ZeroThreshold);
    }
    if signers.is_empty() {
        return Err(MultiSigError::NoSigners);
    }
    if signers.len() > MAX_SIGNERS {
        return Err(MultiSigError::TooManySigners { count: signers.len(), max: MAX_SIGNERS });
    }
    if threshold > signers.len() {
        return Err(MultiSigError::ThresholdExceedsSigners { threshold, signers: signers.len() });
    }
    Ok(())
}

pub fn create_multisig_token(
    owner: u64,
    perms: &[Capability],
    threshold: usize,
    authorized_signers: &[u64],
    ttl_ms: Option<u64>,
) -> Result<MultiSigToken, MultiSigError> {
    validate_params(threshold, authorized_signers)?;
    let expiry = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    Ok(MultiSigToken {
        owner_module: owner,
        permissions: perms.to_vec(),
        expires_at_ms: expiry,
        nonce: default_nonce(),
        threshold,
        authorized_signers: authorized_signers.to_vec(),
        signatures: Vec::with_capacity(threshold),
    })
}

pub fn create_multisig_token_with_nonce(
    owner: u64,
    perms: &[Capability],
    threshold: usize,
    authorized_signers: &[u64],
    ttl_ms: Option<u64>,
    nonce: u64,
) -> Result<MultiSigToken, MultiSigError> {
    validate_params(threshold, authorized_signers)?;
    let expiry = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    Ok(MultiSigToken {
        owner_module: owner,
        permissions: perms.to_vec(),
        expires_at_ms: expiry,
        nonce,
        threshold,
        authorized_signers: authorized_signers.to_vec(),
        signatures: Vec::with_capacity(threshold),
    })
}
