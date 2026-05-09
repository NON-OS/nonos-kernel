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
use crate::wire::constants::SCHEMA_TRUST_ANCHOR_POLICY;

use super::inputs::TrustAnchorPolicyInput;
use super::validate;

pub fn encode(input: &TrustAnchorPolicyInput) -> Result<Vec<u8>, SignError> {
    validate::check(input)?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&SCHEMA_TRUST_ANCHOR_POLICY.to_be_bytes());
    buf.extend_from_slice(&input.epoch.to_be_bytes());
    buf.push(input.keys.len() as u8);
    for k in &input.keys {
        buf.push(k.alg as u8);
        buf.extend_from_slice(&(k.pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&k.pubkey);
        buf.extend_from_slice(&k.valid_from_ms.to_be_bytes());
        buf.extend_from_slice(&k.valid_until_ms.to_be_bytes());
    }
    buf.extend_from_slice(&(input.revoked_cert_serials.len() as u16).to_be_bytes());
    for s in &input.revoked_cert_serials {
        buf.extend_from_slice(&s.to_be_bytes());
    }
    buf.push(input.revoked_nonos_ids.len() as u8);
    for id in &input.revoked_nonos_ids {
        buf.extend_from_slice(id);
    }
    buf.extend_from_slice(&(input.revoked_publisher_key_ids.len() as u16).to_be_bytes());
    for id in &input.revoked_publisher_key_ids {
        buf.extend_from_slice(id);
    }
    buf.extend_from_slice(&input.flags.to_be_bytes());
    Ok(buf)
}
