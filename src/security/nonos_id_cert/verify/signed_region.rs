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

use super::super::error::{IdCertDecodeError, IdCertVerifyError};
use super::super::schema::NonosIdCertificate;

// Re-walk the cert offsets from the already-validated decoded form so
// the signed region never trusts a length field the decoder didn't
// vet first. signed_region = bytes preceding the trust_anchor_signature_count byte.
pub(super) fn compute<'a>(
    cert: &NonosIdCertificate,
    bytes: &'a [u8],
) -> Result<&'a [u8], IdCertVerifyError> {
    let mut off = 0usize;
    off += 2; // schema_version
    off += 8; // cert_serial
    off += 32; // nonos_id
    off += 1; // namespace_glob_count
    for g in &cert.namespace_globs {
        off += 1 + g.len as usize;
    }
    off += 8; // allowed_caps_ceiling
    off += 1 + cert.metadata_len as usize;
    off += 8 + 8 + 8; // valid_from_ms + valid_until_ms + trust_anchor_epoch
    off += 1; // publisher_key_count
    for k in &cert.publisher_keys {
        off += 1 + 16 + 2 + k.pubkey_len as usize;
    }
    if off > bytes.len() {
        return Err(IdCertVerifyError::Decode(IdCertDecodeError::UnexpectedEof));
    }
    Ok(&bytes[..off])
}
