// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::constants::GENERATOR;
use super::generated::GeneratedStealthAddress;
use super::meta_address::StealthMetaAddress;
use super::scalar::normalize_scalar;
use super::utils::{
    fallback_shared_secret, fallback_stealth_address, generate_random_key, pubkey_to_address,
};
use crate::crypto::asymmetric::secp256k1::{
    multiply_point, point_add, public_key_from_secret, scalar_multiply,
};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::vec::Vec;

pub fn generate_stealth_address(
    meta_address: &StealthMetaAddress,
) -> CryptoResult<GeneratedStealthAddress> {
    let ephemeral_key = generate_random_key()?;
    let ephemeral_pubkey =
        public_key_from_secret(&ephemeral_key).ok_or(CryptoError::InvalidInput)?;
    let shared_secret = multiply_point(&meta_address.viewing_pubkey, &ephemeral_key)
        .unwrap_or_else(|_| {
            fallback_shared_secret(&meta_address.viewing_pubkey, &ephemeral_pubkey)
        });
    let mut hash_input = Vec::with_capacity(65);
    hash_input.extend_from_slice(&shared_secret);
    let hashed_secret = normalize_scalar(keccak256(&hash_input));
    let view_tag = hashed_secret[0];
    let stealth_address = scalar_multiply(&GENERATOR, &hashed_secret)
        .and_then(|p| point_add(&meta_address.spending_pubkey, &p))
        .map(|pk| pubkey_to_address(&pk))
        .unwrap_or_else(|_| {
            fallback_stealth_address(&meta_address.spending_pubkey, &shared_secret)
        });
    Ok(GeneratedStealthAddress { stealth_address, ephemeral_pubkey, view_tag })
}
