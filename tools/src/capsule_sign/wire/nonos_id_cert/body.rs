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
use crate::wire::constants::SCHEMA_NONOS_ID_CERT;

use super::inputs::NonosIdCertInputs;
use super::validate;

// Bytes from schema_version through the last publisher key. The trust
// anchor must sign exactly this prefix; the trailing trust_anchor_signature_count
// byte starts the signature trailer.
pub fn encode_signed_region(input: &NonosIdCertInputs) -> Result<Vec<u8>, SignError> {
    validate::check_body(input)?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&SCHEMA_NONOS_ID_CERT.to_be_bytes());
    buf.extend_from_slice(&input.cert_serial.to_be_bytes());
    buf.extend_from_slice(&input.nonos_id);
    buf.push(input.namespace_globs.len() as u8);
    for g in &input.namespace_globs {
        let b = g.as_bytes();
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    buf.extend_from_slice(&input.allowed_caps_ceiling.to_be_bytes());
    let m = input.metadata.as_bytes();
    buf.push(m.len() as u8);
    buf.extend_from_slice(m);
    buf.extend_from_slice(&input.valid_from_ms.to_be_bytes());
    buf.extend_from_slice(&input.valid_until_ms.to_be_bytes());
    buf.extend_from_slice(&input.trust_anchor_epoch.to_be_bytes());
    buf.push(input.publisher_keys.len() as u8);
    for k in &input.publisher_keys {
        buf.push(k.alg as u8);
        buf.extend_from_slice(&k.key_id);
        buf.extend_from_slice(&(k.pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&k.pubkey);
    }
    Ok(buf)
}
