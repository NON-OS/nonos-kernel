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

extern crate alloc;
use alloc::vec::Vec;

mod keys;
mod oaep;
mod pkcs1;
mod pss;

// Re-export BigUint 
pub use crate::crypto::util::bigint::BigUint;
pub use keys::{
    RsaPrivateKey, RsaPublicKey, create_public_key, extract_public_key,
    generate_keypair, generate_keypair_with_bits,
};
pub use oaep::{decrypt, encrypt, oaep_decrypt, oaep_encrypt};
pub use pkcs1::{sign_message, sign_pkcs1v15, verify_pkcs1v15, verify_signature};
pub use pss::{sign_pss, verify_pss};

pub const RSA_2048: usize = 2048;
pub const RSA_3072: usize = 3072;
pub const RSA_4096: usize = 4096;

pub(crate) fn mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    use crate::crypto::hash::sha256;
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;
    while mask.len() < mask_len {
        let mut hasher_input = seed.to_vec();
        hasher_input.extend_from_slice(&counter.to_be_bytes());
        let hash = sha256(&hasher_input);
        mask.extend_from_slice(&hash);
        counter += 1;
    }

    mask.truncate(mask_len);
    mask
}
