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

extern crate alloc;

use alloc::vec::Vec;
use super::super::{NTRU_N, NTRU_SHARED_SECRET_BYTES};

pub(crate) fn hash_to_shared_secret(coeffs: &[i16]) -> [u8; NTRU_SHARED_SECRET_BYTES] {
    use crate::crypto::sha3::sha3_256;

    let mut packed = Vec::with_capacity(NTRU_N);
    for &c in coeffs.iter().take(NTRU_N) {
        let byte = ((c + 1) & 0xFF) as u8;
        packed.push(byte);
    }

    let hash = sha3_256(&packed);
    let mut out = [0u8; NTRU_SHARED_SECRET_BYTES];
    out.copy_from_slice(&hash[..NTRU_SHARED_SECRET_BYTES]);
    out
}
