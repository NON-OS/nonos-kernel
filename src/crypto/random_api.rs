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

/*
 * High-level random number generation API.
 *
 * These functions provide a convenient interface over the underlying
 * ChaCha20-based CSPRNG. They're suitable for general-purpose random
 * byte generation but not for cryptographic key generation (use
 * generate_secure_key() for that, which collects fresh entropy).
 */

use super::error::{CryptoError, CryptoResult};
use super::util::rng;

pub fn fill_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    Ok(())
}

pub fn get_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    Ok(())
}

/*
 * Fills buffer with random bytes if it can hold at least min_entropy bits.
 * This is a sanity check to prevent accidentally using a tiny buffer
 * for security-sensitive operations that need more entropy.
 */
pub fn get_bytes_checked(buffer: &mut [u8], min_entropy: usize) -> CryptoResult<()> {
    if buffer.len() < min_entropy / 8 {
        return Err(CryptoError::BufferTooSmall);
    }
    rng::fill_random_bytes(buffer);
    Ok(())
}
