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

use super::super::cursor::Cursor;
use super::super::error::IdCertDecodeError;
use super::super::schema::MAX_METADATA_LEN;

pub(super) fn decode(
    c: &mut Cursor<'_>,
) -> Result<([u8; MAX_METADATA_LEN], u16), IdCertDecodeError> {
    let mlen = c.u8()? as usize;
    if mlen > MAX_METADATA_LEN {
        return Err(IdCertDecodeError::MetadataLen);
    }
    let mbytes = c.take(mlen)?;
    if core::str::from_utf8(mbytes).is_err() {
        return Err(IdCertDecodeError::MetadataNotUtf8);
    }
    let mut metadata = [0u8; MAX_METADATA_LEN];
    metadata[..mlen].copy_from_slice(mbytes);
    Ok((metadata, mlen as u16))
}
