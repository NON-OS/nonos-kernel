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

use crate::wire::constants::SCHEMA_CAPSULE_MANIFEST;

pub fn derive_capsule_id(
    nonos_id_cert_id: &[u8; 32],
    payload_hash: &[u8; 32],
    namespace: &[u8],
    version_major: u32,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"nonos.capsule.id.v3");
    h.update(&SCHEMA_CAPSULE_MANIFEST.to_be_bytes());
    h.update(nonos_id_cert_id);
    h.update(payload_hash);
    h.update(&[namespace.len() as u8]);
    h.update(namespace);
    h.update(&version_major.to_be_bytes());
    *h.finalize().as_bytes()
}
