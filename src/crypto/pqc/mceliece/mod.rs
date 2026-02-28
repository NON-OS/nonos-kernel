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

extern crate alloc;

mod constants;
mod decaps;
mod encaps;
mod gf;
mod goppa;
mod keygen;
mod serialize;
mod types;
mod util;

pub use constants::{
    mceliece_param_name, MCELIECE_CIPHERTEXT_BYTES, MCELIECE_K, MCELIECE_M, MCELIECE_N,
    MCELIECE_PUBLICKEY_BYTES, MCELIECE_SECRETKEY_BYTES, MCELIECE_SHARED_SECRET_BYTES, MCELIECE_T,
};

pub use decaps::mceliece_decaps;

pub use encaps::mceliece_encaps;

pub use keygen::mceliece_keygen;

pub use serialize::{
    mceliece_deserialize_ciphertext, mceliece_deserialize_public_key,
    mceliece_deserialize_secret_key, mceliece_serialize_ciphertext, mceliece_serialize_public_key,
    mceliece_serialize_secret_key,
};

pub use types::{McElieceCiphertext, McElieceKeyPair, McEliecePublicKey, McElieceSecretKey};

pub(crate) use constants::FIELD_SIZE;
pub(crate) use util::hash_error;
