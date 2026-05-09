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

use super::super::error::{ManifestDecodeError, ManifestVerifyError};
use super::super::schema::CapsuleManifest;

// signed_region = bytes preceding the publisher_signature_count byte.
pub(super) fn compute<'a>(
    manifest: &CapsuleManifest,
    bytes: &'a [u8],
) -> Result<&'a [u8], ManifestVerifyError> {
    let mut off = 0usize;
    off += 2; // schema_version
    off += 32; // nonos_id_cert_id
    off += 1 + manifest.namespace_len as usize;
    off += 12; // version (3 × u32)
    off += 1 + manifest.target_triple_len as usize;
    off += 32; // payload_hash
    off += 8 + 8; // required + optional caps
    off += 1; // endpoint_count
    for e in &manifest.endpoints {
        off += 1 + 4 + 1 + e.name_len as usize;
    }
    if off > bytes.len() {
        return Err(ManifestVerifyError::Decode(ManifestDecodeError::UnexpectedEof));
    }
    Ok(&bytes[..off])
}
