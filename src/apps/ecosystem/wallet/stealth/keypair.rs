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
use super::meta_address::StealthMetaAddress;
use super::scalar::{normalize_scalar, scalar_add};
use super::utils::{
    fallback_shared_secret, fallback_stealth_address, generate_random_key, pubkey_to_address,
};
use crate::crypto::asymmetric::secp256k1::{
    multiply_point, point_add, public_key_from_secret, scalar_multiply, PublicKey, SecretKey,
};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

#[derive(Clone)]
pub struct StealthKeyPair {
    spending_key: SecretKey,
    viewing_key: SecretKey,
    pub(super) spending_pubkey: PublicKey,
    pub(super) viewing_pubkey: PublicKey,
}

impl StealthKeyPair {
    pub fn generate() -> CryptoResult<Self> {
        let (spending_key, viewing_key) = (generate_random_key()?, generate_random_key()?);
        let spending_pubkey =
            public_key_from_secret(&spending_key).ok_or(CryptoError::InvalidInput)?;
        let viewing_pubkey =
            public_key_from_secret(&viewing_key).ok_or(CryptoError::InvalidInput)?;
        Ok(Self { spending_key, viewing_key, spending_pubkey, viewing_pubkey })
    }

    pub fn from_keys(spending_key: SecretKey, viewing_key: SecretKey) -> CryptoResult<Self> {
        let spending_pubkey =
            public_key_from_secret(&spending_key).ok_or(CryptoError::InvalidInput)?;
        let viewing_pubkey =
            public_key_from_secret(&viewing_key).ok_or(CryptoError::InvalidInput)?;
        Ok(Self { spending_key, viewing_key, spending_pubkey, viewing_pubkey })
    }

    pub fn from_master_key(master_key: &[u8; 32]) -> CryptoResult<Self> {
        let spending_key = keccak256(&[master_key.as_slice(), b"stealth-spending"].concat());
        let viewing_key = keccak256(&[master_key.as_slice(), b"stealth-viewing"].concat());
        Self::from_keys(spending_key, viewing_key)
    }

    pub fn spending_pubkey(&self) -> &PublicKey {
        &self.spending_pubkey
    }
    pub fn viewing_pubkey(&self) -> &PublicKey {
        &self.viewing_pubkey
    }
    pub fn meta_address(&self) -> StealthMetaAddress {
        StealthMetaAddress::new(self.spending_pubkey, self.viewing_pubkey)
    }
    pub(super) fn viewing_key(&self) -> &SecretKey {
        &self.viewing_key
    }
    pub(super) fn spending_key(&self) -> &SecretKey {
        &self.spending_key
    }

    pub fn derive_stealth_private_key(
        &self,
        ephemeral_pubkey: &PublicKey,
    ) -> CryptoResult<SecretKey> {
        let shared_secret = multiply_point(ephemeral_pubkey, &self.viewing_key)?;
        let mut hash_input = Vec::with_capacity(65);
        hash_input.extend_from_slice(&shared_secret);
        let hashed_secret = normalize_scalar(keccak256(&hash_input));
        scalar_add(&self.spending_key, &hashed_secret)
    }

    pub fn can_spend(&self, stealth_address: &[u8; 20], ephemeral_pubkey: &PublicKey) -> bool {
        let shared_secret = multiply_point(ephemeral_pubkey, &self.viewing_key)
            .unwrap_or_else(|_| fallback_shared_secret(&self.viewing_pubkey, ephemeral_pubkey));
        let mut hash_input = Vec::with_capacity(65);
        hash_input.extend_from_slice(&shared_secret);
        let hashed_secret = keccak256(&hash_input);
        let derived = scalar_multiply(&GENERATOR, &hashed_secret)
            .and_then(|p| point_add(&self.spending_pubkey, &p))
            .map(|pk| pubkey_to_address(&pk))
            .unwrap_or_else(|_| fallback_stealth_address(&self.spending_pubkey, &shared_secret));
        derived == *stealth_address
    }
}

impl Drop for StealthKeyPair {
    fn drop(&mut self) {
        for byte in self.spending_key.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        for byte in self.viewing_key.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
