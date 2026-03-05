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

mod constants;
mod decaps;
mod encaps;
mod keygen;
mod poly;
mod serialize;
mod types;

pub use constants::{
    ntru_param_name, NTRU_CIPHERTEXT_BYTES, NTRU_LOG_Q, NTRU_N, NTRU_PUBLICKEY_BYTES, NTRU_Q,
    NTRU_SECRETKEY_BYTES, NTRU_SHARED_SECRET_BYTES,
};

pub use decaps::ntru_decaps;

pub use encaps::ntru_encaps;

pub use keygen::ntru_keygen;

pub use serialize::{
    ntru_deserialize_ciphertext, ntru_deserialize_public_key, ntru_deserialize_secret_key,
    ntru_serialize_ciphertext, ntru_serialize_public_key, ntru_serialize_secret_key,
};

pub use types::{NtruCiphertext, NtruKeyPair, NtruPublicKey, NtruSecretKey};

pub(crate) use constants::NTRU_WEIGHT;
