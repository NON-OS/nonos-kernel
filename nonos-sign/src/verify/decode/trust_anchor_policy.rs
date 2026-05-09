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
use crate::verify::cursor::Cursor;
use crate::verify::decoded::{DecodedTaKey, DecodedTaPolicy};
use crate::wire::constants::SCHEMA_TRUST_ANCHOR_POLICY;

pub fn decode_trust_anchor_policy(bytes: &[u8]) -> Result<DecodedTaPolicy, SignError> {
    let mut c = Cursor::new(bytes);
    if c.u16_be()? != SCHEMA_TRUST_ANCHOR_POLICY {
        return Err(SignError::KeyFileShape("ta-policy schema_version mismatch".into()));
    }
    let epoch = c.u64_be()?;
    let key_count = c.u8()? as usize;
    let mut keys: Vec<DecodedTaKey> = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let plen = c.u16_be()? as usize;
        let pubkey = c.take(plen)?.to_vec();
        let valid_from_ms = c.u64_be()?;
        let valid_until_ms = c.u64_be()?;
        keys.push(DecodedTaKey { alg, pubkey, valid_from_ms, valid_until_ms });
    }
    let serial_count = c.u16_be()? as usize;
    let mut revoked_cert_serials: Vec<u64> = Vec::with_capacity(serial_count);
    for _ in 0..serial_count {
        revoked_cert_serials.push(c.u64_be()?);
    }
    let id_count = c.u8()? as usize;
    let mut revoked_nonos_ids: Vec<[u8; 32]> = Vec::with_capacity(id_count);
    for _ in 0..id_count {
        revoked_nonos_ids.push(c.array::<32>()?);
    }
    let key_id_count = c.u16_be()? as usize;
    let mut revoked_publisher_key_ids: Vec<[u8; 16]> = Vec::with_capacity(key_id_count);
    for _ in 0..key_id_count {
        revoked_publisher_key_ids.push(c.array::<16>()?);
    }
    let flags = c.u32_be()?;
    if !c.at_end() {
        return Err(SignError::KeyFileShape("ta-policy trailing bytes".into()));
    }
    Ok(DecodedTaPolicy {
        epoch,
        keys,
        revoked_cert_serials,
        revoked_nonos_ids,
        revoked_publisher_key_ids,
        flags,
    })
}
