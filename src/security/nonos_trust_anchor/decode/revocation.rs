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

use super::super::cursor::Cursor;
use super::super::error::TrustAnchorDecodeError;
use super::super::schema::{
    MAX_REVOKED_CERT_SERIALS, MAX_REVOKED_NONOS_IDS, MAX_REVOKED_PUBLISHER_KEY_IDS, NONOS_ID_LEN,
    PUBLISHER_KEY_ID_LEN,
};

pub(super) struct Revocation {
    pub revoked_cert_serials: Vec<u64>,
    pub revoked_nonos_ids: Vec<[u8; NONOS_ID_LEN]>,
    pub revoked_publisher_key_ids: Vec<[u8; PUBLISHER_KEY_ID_LEN]>,
}

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Revocation, TrustAnchorDecodeError> {
    let serial_count = c.u16_be()? as usize;
    if serial_count > MAX_REVOKED_CERT_SERIALS {
        return Err(TrustAnchorDecodeError::RevokedCertSerialCount);
    }
    let mut revoked_cert_serials: Vec<u64> = Vec::with_capacity(serial_count);
    for _ in 0..serial_count {
        revoked_cert_serials.push(c.u64_be()?);
    }

    let id_count = c.u8()? as usize;
    if id_count > MAX_REVOKED_NONOS_IDS {
        return Err(TrustAnchorDecodeError::RevokedNonosIdCount);
    }
    let mut revoked_nonos_ids: Vec<[u8; NONOS_ID_LEN]> = Vec::with_capacity(id_count);
    for _ in 0..id_count {
        revoked_nonos_ids.push(c.array::<NONOS_ID_LEN>()?);
    }

    let key_id_count = c.u16_be()? as usize;
    if key_id_count > MAX_REVOKED_PUBLISHER_KEY_IDS {
        return Err(TrustAnchorDecodeError::RevokedPublisherKeyIdCount);
    }
    let mut revoked_publisher_key_ids: Vec<[u8; PUBLISHER_KEY_ID_LEN]> =
        Vec::with_capacity(key_id_count);
    for _ in 0..key_id_count {
        revoked_publisher_key_ids.push(c.array::<PUBLISHER_KEY_ID_LEN>()?);
    }

    Ok(Revocation { revoked_cert_serials, revoked_nonos_ids, revoked_publisher_key_ids })
}
