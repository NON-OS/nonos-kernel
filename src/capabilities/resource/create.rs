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

use super::error::ResourceError;
use super::nonce::next_nonce;
use super::quota::ResourceQuota;
use super::sign::sign_resource_token;
use super::token::ResourceToken;

pub fn create_resource_token(
    owner: u64,
    quota: ResourceQuota,
) -> Result<ResourceToken, ResourceError> {
    if quota.is_empty() {
        return Err(ResourceError::ZeroQuota);
    }

    let nonce = next_nonce();
    let mut token = ResourceToken {
        owner_module: owner,
        original_quota: quota,
        remaining_bytes: quota.bytes,
        remaining_ops: quota.ops,
        nonce,
        signature: [0u8; 64],
    };

    sign_resource_token(&mut token)?;
    Ok(token)
}

pub fn create_resource_token_with_nonce(
    owner: u64,
    quota: ResourceQuota,
    nonce: u64,
) -> Result<ResourceToken, ResourceError> {
    if quota.is_empty() {
        return Err(ResourceError::ZeroQuota);
    }

    let mut token = ResourceToken {
        owner_module: owner,
        original_quota: quota,
        remaining_bytes: quota.bytes,
        remaining_ops: quota.ops,
        nonce,
        signature: [0u8; 64],
    };

    sign_resource_token(&mut token)?;
    Ok(token)
}
