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
use super::super::error::IdCertDecodeError;
use super::super::schema::{
    PublisherKey, MAX_KEYS_PER_ALG, MAX_PUBLISHER_KEYS, PUBLISHER_KEY_ID_LEN,
};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<PublisherKey>, IdCertDecodeError> {
    let count = c.u8()? as usize;
    if count == 0 || count > MAX_PUBLISHER_KEYS {
        return Err(IdCertDecodeError::PublisherKeyCount);
    }
    let mut keys: Vec<PublisherKey> = Vec::with_capacity(count);
    for _ in 0..count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let key_id = c.array::<PUBLISHER_KEY_ID_LEN>()?;
        let plen = c.u16_be()? as usize;
        let expected = pubkey_len(alg);
        if plen != expected {
            return Err(IdCertDecodeError::PubkeyLen { expected, got: plen });
        }
        let pbytes = c.take(plen)?;
        let mut pubkey = [0u8; MAX_PUBKEY_BYTES];
        pubkey[..plen].copy_from_slice(pbytes);
        let same_alg = keys.iter().filter(|k| k.algorithm == alg).count();
        if same_alg >= MAX_KEYS_PER_ALG {
            return Err(IdCertDecodeError::PublisherKeysPerAlg);
        }
        keys.push(PublisherKey {
            algorithm: alg,
            key_id,
            pubkey,
            pubkey_len: plen as u16,
        });
    }
    Ok(keys)
}
