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

mod address;
mod fors;
mod hash;
mod hypertree;
mod types;
mod serialize;
mod sign;
mod verify;
mod wots;

pub use types::{SphincsKeyPair, SphincsPublicKey, SphincsSecretKey, SphincsSignature};
pub use serialize::{
    sphincs_deserialize_public_key, sphincs_deserialize_secret_key, sphincs_deserialize_signature,
    sphincs_serialize_public_key, sphincs_serialize_secret_key, sphincs_serialize_signature,
};
pub use sign::{sphincs_keygen, sphincs_sign};
pub use verify::sphincs_verify;

pub(crate) use address::Address;
pub(crate) use fors::{fors_pk_from_sig, fors_sign};
pub(crate) use hash::{hash_message, prf, prf_msg, thash};
pub(crate) use hypertree::{compute_auth_path, treehash};
pub(crate) use wots::{wots_pk_from_sig, wots_pk_gen, wots_sign};

pub const SPHINCS_N: usize = 16;
pub const SPHINCS_H: usize = 63;
pub const SPHINCS_D: usize = 7;
pub const SPHINCS_K: usize = 14;
pub const SPHINCS_A: usize = 12;
pub const SPHINCS_W: usize = 16;

pub const SPHINCS_WOTS_LEN1: usize = 2 * SPHINCS_N;
pub const SPHINCS_WOTS_LEN2: usize = 3;
pub const SPHINCS_WOTS_LEN: usize = SPHINCS_WOTS_LEN1 + SPHINCS_WOTS_LEN2;
pub const SPHINCS_WOTS_SIG_BYTES: usize = SPHINCS_WOTS_LEN * SPHINCS_N;

pub const SPHINCS_FORS_MSG_BYTES: usize = (SPHINCS_K * SPHINCS_A + 7) / 8;
pub const SPHINCS_FORS_SIG_BYTES: usize = SPHINCS_K * (SPHINCS_A + 1) * SPHINCS_N;

pub const SPHINCS_SK_SEED_BYTES: usize = SPHINCS_N;
pub const SPHINCS_SK_PRF_BYTES: usize = SPHINCS_N;
pub const SPHINCS_PK_SEED_BYTES: usize = SPHINCS_N;
pub const SPHINCS_PK_ROOT_BYTES: usize = SPHINCS_N;

pub const SPHINCS_SK_BYTES: usize = 2 * SPHINCS_N + SPHINCS_PK_BYTES;
pub const SPHINCS_PK_BYTES: usize = 2 * SPHINCS_N;

pub const SPHINCS_SIG_BYTES: usize = SPHINCS_N
    + SPHINCS_FORS_SIG_BYTES
    + SPHINCS_D * (SPHINCS_WOTS_SIG_BYTES + (SPHINCS_H / SPHINCS_D) * SPHINCS_N);

pub const fn sphincs_param_name() -> &'static str {
    "SPHINCS+-128s-simple"
}
