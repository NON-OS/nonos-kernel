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

use super::constants::MCELIECE_SHARED_SECRET_BYTES;

pub(crate) fn hash_error(error: &[u8]) -> [u8; MCELIECE_SHARED_SECRET_BYTES] {
    use crate::crypto::sha3::sha3_256;

    let hash = sha3_256(error);
    let mut out = [0u8; MCELIECE_SHARED_SECRET_BYTES];
    out.copy_from_slice(&hash[..MCELIECE_SHARED_SECRET_BYTES]);
    out
}
