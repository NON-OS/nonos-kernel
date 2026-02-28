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

use super::core::hmac_sha256;

pub fn totp_hmac_sha256(key: &[u8], time_step: u64, digits: usize) -> u32 {
    let time_bytes = time_step.to_be_bytes();
    let mac = hmac_sha256(key, &time_bytes);
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = ((mac[offset] & 0x7f) as u32) << 24
                | (mac[offset + 1] as u32) << 16
                | (mac[offset + 2] as u32) << 8
                | (mac[offset + 3] as u32);
    let modulus = 10_u32.pow(digits as u32);
    binary % modulus
}

pub fn hotp_hmac_sha256(key: &[u8], counter: u64, digits: usize) -> u32 {
    totp_hmac_sha256(key, counter, digits)
}
