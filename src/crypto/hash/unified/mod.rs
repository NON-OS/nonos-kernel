// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod sha256;
mod sha3;
mod blake3;
mod hmac;
mod hkdf;
#[cfg(feature = "sha1-legacy")]
mod sha1;

#[cfg(test)]
mod tests;

pub type Hash256 = [u8; 32];

pub use sha256::sha256;
pub use sha3::sha3_256_hash;
pub use blake3::blake3_hash;
pub use hmac::{hmac_sha256, hmac_verify};
pub use hkdf::{hkdf_extract, hkdf_expand};

#[cfg(feature = "sha1-legacy")]
#[allow(deprecated)]
pub use sha1::sha1;
