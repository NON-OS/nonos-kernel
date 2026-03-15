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

pub mod curve;
pub mod aead;
pub mod kdf;
pub mod lioness;
pub mod keys;

pub use curve::{x25519_scalar_mult, x25519_base_point_mult, generate_keypair};
pub use aead::{aes_gcm_encrypt, aes_gcm_decrypt};
pub use kdf::{hkdf_sha256, derive_key};
pub use lioness::{lioness_encrypt, lioness_decrypt};
pub use keys::{SphinxKeys, derive_sphinx_keys};
