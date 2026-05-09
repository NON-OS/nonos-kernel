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

mod header;
mod metadata;
mod namespace_globs;
mod publisher_keys;
mod trust_anchor_sigs;

use super::cursor::Cursor;
use super::error::IdCertDecodeError;
use super::schema::NonosIdCertificate;

pub fn decode(bytes: &[u8]) -> Result<NonosIdCertificate, IdCertDecodeError> {
    let mut c = Cursor::new(bytes);
    let h = header::decode(&mut c)?;
    let publisher_keys = publisher_keys::decode(&mut c)?;
    let trust_anchor_signatures = trust_anchor_sigs::decode(&mut c)?;
    if c.pos != bytes.len() {
        return Err(IdCertDecodeError::TrailingBytes);
    }
    Ok(NonosIdCertificate {
        schema_version: super::schema::ID_CERT_SCHEMA_VERSION,
        cert_serial: h.cert_serial,
        nonos_id: h.nonos_id,
        namespace_globs: h.namespace_globs,
        allowed_caps_ceiling: h.allowed_caps_ceiling,
        metadata: h.metadata,
        metadata_len: h.metadata_len,
        valid_from_ms: h.valid_from_ms,
        valid_until_ms: h.valid_until_ms,
        trust_anchor_epoch: h.trust_anchor_epoch,
        publisher_keys,
        trust_anchor_signatures,
    })
}
