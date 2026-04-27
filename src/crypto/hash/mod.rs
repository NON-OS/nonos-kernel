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

pub mod blake3;
pub mod sha3;
pub mod sha384;
pub mod sha512;
pub mod unified;

pub use blake3::{blake3_derive_key, blake3_hash, blake3_hash_xof, blake3_keyed_hash};
pub use sha3::{keccak256, sha3_256, sha3_512, shake128, shake256};
pub use sha3::{Keccak256, Sha3_256, Sha3_512, Shake128, Shake256};
pub use sha512::{sha512, sha512_hash, Hash512};
pub use unified::{hkdf_expand, hmac_sha256, hmac_verify, ripemd160, sha256, Hash256};
pub use unified::{hkdf_expand_sha384, hkdf_extract_sha384, hmac_sha384};

// SHA-1 is needed for WPA authentication (legacy but required for compatibility)
#[allow(deprecated)]
pub use unified::sha1;
