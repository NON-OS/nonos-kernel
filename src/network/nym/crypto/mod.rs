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

pub mod aead;
pub mod curve;
pub mod kdf;
pub mod keys;
pub mod lioness;

pub use aead::{aes_gcm_decrypt, aes_gcm_encrypt};
pub use curve::{generate_keypair, x25519_base_point_mult, x25519_scalar_mult};
pub use kdf::{derive_key, hkdf_sha256};
pub use keys::{derive_sphinx_keys, SphinxKeys};
pub use lioness::{lioness_decrypt, lioness_encrypt};
