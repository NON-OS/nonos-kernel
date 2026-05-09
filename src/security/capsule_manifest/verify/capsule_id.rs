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

use super::super::schema::{CapsuleManifest, MANIFEST_SCHEMA_VERSION};

pub(super) fn derive(manifest: &CapsuleManifest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nonos.capsule.id.v3");
    hasher.update(&MANIFEST_SCHEMA_VERSION.to_be_bytes());
    hasher.update(&manifest.nonos_id_cert_id);
    hasher.update(&manifest.payload_hash);
    hasher.update(&[manifest.namespace_len]);
    hasher.update(&manifest.namespace[..manifest.namespace_len as usize]);
    hasher.update(&manifest.version.major.to_be_bytes());
    *hasher.finalize().as_bytes()
}
