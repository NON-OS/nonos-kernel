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

use super::manifest::AppManifest;
use alloc::vec::Vec;

pub(super) fn manifest_to_bytes(m: &AppManifest) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(&m.id);
    b.extend_from_slice(&m.name);
    b.extend_from_slice(&m.version);
    b.extend_from_slice(&m.author);
    b.extend_from_slice(&m.author_addr);
    b.extend_from_slice(&m.price_nox.to_le_bytes());
    b.push(m.category);
    b.push(m.perm_count);
    b
}

pub(super) fn bytes_to_manifest(b: &[u8]) -> Option<AppManifest> {
    if b.len() < 140 {
        return None;
    }
    let mut m = AppManifest::empty();
    m.id.copy_from_slice(&b[0..32]);
    m.name.copy_from_slice(&b[32..96]);
    m.version.copy_from_slice(&b[96..112]);
    m.author.copy_from_slice(&b[112..176]);
    m.author_addr.copy_from_slice(&b[176..196]);
    m.price_nox = u32::from_le_bytes([b[196], b[197], b[198], b[199]]);
    m.category = b[200];
    m.perm_count = b[201];
    Some(m)
}
