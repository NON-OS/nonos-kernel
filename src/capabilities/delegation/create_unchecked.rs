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

use crate::capabilities::types::Capability;

use super::error::DelegationError;
use super::sign::sign_delegation;
use super::types::Delegation;

pub fn create_delegation_unchecked(
    delegator: u64,
    delegatee: u64,
    caps: &[Capability],
    expires_at_ms: Option<u64>,
    parent_nonce: u64,
) -> Result<Delegation, DelegationError> {
    if caps.is_empty() {
        return Err(DelegationError::NoCapabilities);
    }
    let mut delegation = Delegation {
        delegator,
        delegatee,
        capabilities: caps.to_vec(),
        expires_at_ms,
        parent_nonce,
        signature: [0u8; 64],
    };
    sign_delegation(&mut delegation)?;
    Ok(delegation)
}
