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
use crate::wire::constants::SCHEMA_CAPSULE_MANIFEST;

use super::inputs::CapsuleManifestInputs;
use super::validate;

// Bytes from schema_version through the last endpoint. The publisher
// must sign exactly this prefix; the trailing publisher_signature_count
// byte starts the signature trailer.
pub fn encode_signed_region(input: &CapsuleManifestInputs) -> Result<Vec<u8>, SignError> {
    validate::check_body(input)?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&SCHEMA_CAPSULE_MANIFEST.to_be_bytes());
    buf.extend_from_slice(&input.nonos_id_cert_id);
    let ns = input.namespace.as_bytes();
    buf.push(ns.len() as u8);
    buf.extend_from_slice(ns);
    buf.extend_from_slice(&input.version.major.to_be_bytes());
    buf.extend_from_slice(&input.version.minor.to_be_bytes());
    buf.extend_from_slice(&input.version.patch.to_be_bytes());
    let tt = input.target_triple.as_bytes();
    buf.push(tt.len() as u8);
    buf.extend_from_slice(tt);
    buf.extend_from_slice(&input.payload_hash);
    buf.extend_from_slice(&input.required_caps.to_be_bytes());
    buf.extend_from_slice(&input.optional_caps.to_be_bytes());
    buf.push(input.endpoints.len() as u8);
    for e in &input.endpoints {
        buf.push(e.kind as u8);
        buf.extend_from_slice(&e.port.to_be_bytes());
        let nb = e.name.as_bytes();
        buf.push(nb.len() as u8);
        buf.extend_from_slice(nb);
    }
    Ok(buf)
}
