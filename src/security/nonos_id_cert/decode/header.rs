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
use super::super::error::IdCertDecodeError;
use super::super::schema::{NamespaceGlob, ID_CERT_SCHEMA_VERSION, MAX_METADATA_LEN, NONOS_ID_LEN};
use super::{metadata, namespace_globs};

pub(super) struct Header {
    pub cert_serial: u64,
    pub nonos_id: [u8; NONOS_ID_LEN],
    pub namespace_globs: Vec<NamespaceGlob>,
    pub allowed_caps_ceiling: u64,
    pub metadata: [u8; MAX_METADATA_LEN],
    pub metadata_len: u16,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub trust_anchor_epoch: u64,
}

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Header, IdCertDecodeError> {
    if c.u16_be()? != ID_CERT_SCHEMA_VERSION {
        return Err(IdCertDecodeError::SchemaVersion);
    }
    let cert_serial = c.u64_be()?;
    let nonos_id = c.array::<NONOS_ID_LEN>()?;
    let namespace_globs = namespace_globs::decode(c)?;
    let allowed_caps_ceiling = c.u64_be()?;
    let (metadata, metadata_len) = metadata::decode(c)?;
    let valid_from_ms = c.u64_be()?;
    let valid_until_ms = c.u64_be()?;
    if valid_from_ms == 0 || valid_until_ms <= valid_from_ms {
        return Err(IdCertDecodeError::ValidityWindow);
    }
    let trust_anchor_epoch = c.u64_be()?;
    Ok(Header {
        cert_serial,
        nonos_id,
        namespace_globs,
        allowed_caps_ceiling,
        metadata,
        metadata_len,
        valid_from_ms,
        valid_until_ms,
        trust_anchor_epoch,
    })
}
