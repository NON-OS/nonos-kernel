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

mod aead;
mod hash;
mod keygen;
mod random;
mod sign;
mod zk;

pub use aead::{handle_crypto_decrypt, handle_crypto_encrypt};
pub use hash::handle_crypto_hash;
pub use keygen::handle_crypto_keygen;
pub use random::handle_crypto_random;
pub use sign::{handle_crypto_sign, handle_crypto_verify};
pub use zk::{handle_crypto_zk_prove, handle_crypto_zk_verify};
