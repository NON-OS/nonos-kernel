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

mod endpoints;
mod header;
mod publisher_sigs;

use super::cursor::Cursor;
use super::error::ManifestDecodeError;
use super::schema::{CapsuleManifest, MANIFEST_SCHEMA_VERSION};

pub fn decode(bytes: &[u8]) -> Result<CapsuleManifest, ManifestDecodeError> {
    let mut c = Cursor::new(bytes);
    let h = header::decode(&mut c)?;
    let endpoints_vec = endpoints::decode(&mut c)?;
    let publisher_signatures = publisher_sigs::decode(&mut c)?;
    if c.pos != bytes.len() {
        return Err(ManifestDecodeError::TrailingBytes);
    }
    Ok(CapsuleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        nonos_id_cert_id: h.nonos_id_cert_id,
        namespace: h.namespace,
        namespace_len: h.namespace_len,
        version: h.version,
        target_triple: h.target_triple,
        target_triple_len: h.target_triple_len,
        payload_hash: h.payload_hash,
        required_caps: h.required_caps,
        optional_caps: h.optional_caps,
        endpoints: endpoints_vec,
        publisher_signatures,
    })
}
