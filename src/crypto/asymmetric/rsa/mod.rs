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
mod keys;
mod mgf;
mod oaep;
mod pkcs1;
mod pss;

pub use crate::crypto::util::bigint::BigUint;

pub use constants::{RSA_2048, RSA_3072, RSA_4096};

pub use keys::{
    create_public_key, extract_public_key, generate_keypair, generate_keypair_with_bits,
    RsaPrivateKey, RsaPublicKey,
};

pub use oaep::{decrypt, encrypt, oaep_decrypt, oaep_encrypt};

pub use pkcs1::{sign_message, sign_pkcs1v15, verify_pkcs1v15, verify_signature};

pub use pss::{sign_pss, verify_pss};

pub(crate) use mgf::mgf1;
