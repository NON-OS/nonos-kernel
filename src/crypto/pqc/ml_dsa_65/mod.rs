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

mod api;
mod constants;
mod ffi;
mod types;

pub use api::{
    ml_dsa_65_deserialize_public_key, ml_dsa_65_deserialize_secret_key,
    ml_dsa_65_deserialize_signature, ml_dsa_65_keypair, ml_dsa_65_serialize_public_key,
    ml_dsa_65_serialize_secret_key, ml_dsa_65_serialize_signature, ml_dsa_65_sign,
    ml_dsa_65_verify,
};
pub use constants::{PARAM_NAME, PUBLICKEY_BYTES, SECRETKEY_BYTES, SIGNATURE_BYTES};
pub use types::{
    MlDsa65Error, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
