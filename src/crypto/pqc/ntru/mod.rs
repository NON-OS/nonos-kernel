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

mod poly;
mod types;
mod serialize;
mod keygen;
mod encaps;
mod decaps;

pub use types::{NtruCiphertext, NtruKeyPair, NtruPublicKey, NtruSecretKey};
pub use serialize::{
    ntru_deserialize_ciphertext, ntru_deserialize_public_key, ntru_deserialize_secret_key,
    ntru_serialize_ciphertext, ntru_serialize_public_key, ntru_serialize_secret_key,
};
pub use keygen::ntru_keygen;
pub use encaps::ntru_encaps;
pub use decaps::ntru_decaps;

pub const NTRU_N: usize = 821;
pub const NTRU_Q: u16 = 4096;
pub const NTRU_LOG_Q: usize = 12;
pub const NTRU_PUBLICKEY_BYTES: usize = (NTRU_N * NTRU_LOG_Q + 7) / 8;
pub const NTRU_SECRETKEY_BYTES: usize = NTRU_N + NTRU_PUBLICKEY_BYTES;
pub const NTRU_CIPHERTEXT_BYTES: usize = (NTRU_N * NTRU_LOG_Q + 7) / 8;
pub const NTRU_SHARED_SECRET_BYTES: usize = 32;

pub(crate) const NTRU_WEIGHT: usize = 286;

pub const fn ntru_param_name() -> &'static str {
    "NTRU-HPS-4096-821"
}
