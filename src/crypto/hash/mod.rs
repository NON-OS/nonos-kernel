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

pub mod sha512;
pub mod sha3;
pub mod blake3;
pub mod unified;

pub use sha512::{sha512, Hash512};
pub use sha3::{sha3_256, sha3_512, shake128, shake256, keccak256};
pub use sha3::{Sha3_256, Sha3_512, Shake128, Shake256, Keccak256};
pub use blake3::{blake3_hash, blake3_keyed_hash, blake3_derive_key, blake3_hash_xof};
pub use unified::{sha256, hmac_sha256, hmac_verify, hkdf_expand, Hash256};

#[cfg(feature = "sha1-legacy")]
#[allow(deprecated)]
pub use unified::sha1;
