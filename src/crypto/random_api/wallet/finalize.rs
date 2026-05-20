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

pub(super) fn fill_output(buffer: &mut [u8], entropy_pool: &[u8]) {
    let hash = crate::crypto::blake3_hash(entropy_pool);

    if buffer.len() <= hash.len() {
        buffer.copy_from_slice(&hash[..buffer.len()]);
    } else {
        let mut hasher = blake3::Hasher::new();
        hasher.update(entropy_pool);
        hasher.finalize_xof().fill(buffer);
    }
}
