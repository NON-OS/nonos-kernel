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

use super::entropy_check::required_entropy_bytes;
use super::hardware_mix::mix_hardware_entropy;
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::util::rng;

pub fn fill_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    Ok(())
}

pub fn get_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    fill_bytes(buffer)
}

pub fn get_bytes_checked(buffer: &mut [u8], min_entropy: usize) -> CryptoResult<()> {
    if buffer.len() < required_entropy_bytes(min_entropy) {
        return Err(CryptoError::BufferTooSmall);
    }
    fill_bytes(buffer)
}

pub fn get_bytes_secure(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    mix_hardware_entropy(buffer);
    Ok(())
}
