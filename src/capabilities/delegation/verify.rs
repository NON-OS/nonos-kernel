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

use crate::capabilities::token::{signing_key, CapabilityToken};

use super::error::DelegationError;
use super::material::{compute_delegation_signature, delegation_material};
use super::types::Delegation;

pub fn verify_delegation(d: &Delegation, parent: &CapabilityToken) -> bool {
    if d.is_expired() {
        return false;
    }

    if d.parent_nonce != parent.nonce {
        return false;
    }

    if d.delegator != parent.owner_module {
        return false;
    }

    let Some(key) = signing_key() else {
        return false;
    };

    let mat = delegation_material(d, parent.nonce);
    let expected = compute_delegation_signature(key, &mat);

    d.signature == expected
}

pub fn verify_delegation_strict(
    d: &Delegation,
    parent: &CapabilityToken,
) -> Result<(), DelegationError> {
    if d.is_expired() {
        return Err(DelegationError::DelegationExpired);
    }

    if d.parent_nonce != parent.nonce || d.delegator != parent.owner_module {
        return Err(DelegationError::InvalidParentToken);
    }

    let Some(key) = signing_key() else {
        return Err(DelegationError::MissingSigningKey);
    };

    let mat = delegation_material(d, parent.nonce);
    let expected = compute_delegation_signature(key, &mat);

    if d.signature != expected {
        return Err(DelegationError::InvalidSignature);
    }

    Ok(())
}

pub fn verify_delegation_standalone(d: &Delegation) -> bool {
    if d.is_expired() {
        return false;
    }

    let Some(key) = signing_key() else {
        return false;
    };

    let mat = delegation_material(d, d.parent_nonce);
    let expected = compute_delegation_signature(key, &mat);

    d.signature == expected
}
