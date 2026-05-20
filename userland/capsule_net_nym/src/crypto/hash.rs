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

use nonos_libc::crypto_hash;

use super::types::CryptoError;

const ALGO_BLAKE3: u64 = 0;

pub fn blake3(input: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
    let n = crypto_hash(ALGO_BLAKE3, input.as_ptr(), input.len(), out.as_mut_ptr(), out.len());
    if n == out.len() as i64 {
        Ok(())
    } else {
        Err(CryptoError::Hash)
    }
}
