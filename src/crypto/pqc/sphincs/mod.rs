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

mod address;
mod constants;
mod fors;
mod hash;
mod hypertree;
mod serialize;
mod sign;
mod types;
mod verify;
mod wots;

pub use constants::{
    sphincs_param_name, SPHINCS_A, SPHINCS_D, SPHINCS_FORS_MSG_BYTES, SPHINCS_FORS_SIG_BYTES,
    SPHINCS_H, SPHINCS_K, SPHINCS_N, SPHINCS_PK_BYTES, SPHINCS_PK_ROOT_BYTES, SPHINCS_PK_SEED_BYTES,
    SPHINCS_SIG_BYTES, SPHINCS_SK_BYTES, SPHINCS_SK_PRF_BYTES, SPHINCS_SK_SEED_BYTES, SPHINCS_W,
    SPHINCS_WOTS_LEN, SPHINCS_WOTS_LEN1, SPHINCS_WOTS_LEN2, SPHINCS_WOTS_SIG_BYTES,
};

pub use serialize::{
    sphincs_deserialize_public_key, sphincs_deserialize_secret_key, sphincs_deserialize_signature,
    sphincs_serialize_public_key, sphincs_serialize_secret_key, sphincs_serialize_signature,
};

pub use sign::{sphincs_keygen, sphincs_sign};

pub use types::{SphincsKeyPair, SphincsPublicKey, SphincsSecretKey, SphincsSignature};

pub use verify::sphincs_verify;
