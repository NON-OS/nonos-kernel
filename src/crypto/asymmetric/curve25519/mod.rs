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

#![allow(clippy::needless_range_loop)]

mod ed25519;
mod field;
mod util;
mod x25519;

#[cfg(test)]
mod tests;

pub use ed25519::*;

pub use field::FieldElement;

pub use util::scalarmult_base;

pub use x25519::{
    compute_shared_secret, derive_public_key, x25519, x25519_base, x25519_keypair,
    X25519PrivateKey, X25519PublicKey, X25519SharedSecret,
};

pub(crate) use util::{load_u64_le, store_u64_le, SQRT_M1};
