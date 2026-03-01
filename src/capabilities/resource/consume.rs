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
use super::sign::sign_resource_token;
use super::token::ResourceToken;

pub fn try_consume(token: &mut ResourceToken, bytes: u64, ops: u64) -> Result<(), ResourceError> {
    if token.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    if !token.has_bytes(bytes) {
        return Err(ResourceError::InsufficientBytes {
            requested: bytes,
            available: token.remaining_bytes(),
        });
    }

    if !token.has_ops(ops) {
        return Err(ResourceError::InsufficientOps {
            requested: ops,
            available: token.remaining_ops(),
        });
    }

    token.consume_bytes(bytes)?;
    token.consume_ops(ops)?;

    Ok(())
}

pub fn try_consume_bytes(token: &mut ResourceToken, bytes: u64) -> Result<(), ResourceError> {
    if token.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    token.consume_bytes(bytes)
}

pub fn try_consume_ops(token: &mut ResourceToken, ops: u64) -> Result<(), ResourceError> {
    if token.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    token.consume_ops(ops)
}

pub fn reset_token(token: &mut ResourceToken) -> Result<(), ResourceError> {
    token.remaining_bytes = token.original_quota.bytes;
    token.remaining_ops = token.original_quota.ops;
    token.nonce = next_nonce();
    sign_resource_token(token)
}

pub fn refund_bytes(token: &mut ResourceToken, bytes: u64) {
    let max_refund = token.bytes_used();
    let actual_refund = bytes.min(max_refund);
    token.remaining_bytes += actual_refund;
}

pub fn refund_ops(token: &mut ResourceToken, ops: u64) {
    let max_refund = token.ops_used();
    let actual_refund = ops.min(max_refund);
    token.remaining_ops += actual_refund;
}
