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

use alloc::vec::Vec;

use crate::crypto::asymmetric::alg_id::{pubkey_len, AlgId, MAX_PUBKEY_BYTES};

use super::super::cursor::Cursor;
use super::super::error::TrustAnchorDecodeError;
use super::super::schema::{TrustAnchorKey, MAX_TRUST_ANCHOR_KEYS};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<TrustAnchorKey>, TrustAnchorDecodeError> {
    let count = c.u8()? as usize;
    if count == 0 || count > MAX_TRUST_ANCHOR_KEYS {
        return Err(TrustAnchorDecodeError::KeyCount);
    }
    let mut keys: Vec<TrustAnchorKey> = Vec::with_capacity(count);
    for _ in 0..count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let plen = c.u16_be()? as usize;
        let expected = pubkey_len(alg);
        if plen != expected {
            return Err(TrustAnchorDecodeError::PubkeyLen { expected, got: plen });
        }
        let pbytes = c.take(plen)?;
        let mut pubkey = [0u8; MAX_PUBKEY_BYTES];
        pubkey[..plen].copy_from_slice(pbytes);
        let valid_from_ms = c.u64_be()?;
        let valid_until_ms = c.u64_be()?;
        if valid_from_ms == 0 || (valid_until_ms != 0 && valid_until_ms <= valid_from_ms) {
            return Err(TrustAnchorDecodeError::ValidityWindow);
        }
        keys.push(TrustAnchorKey {
            algorithm: alg,
            pubkey,
            pubkey_len: plen as u16,
            valid_from_ms,
            valid_until_ms,
        });
    }
    Ok(keys)
}
