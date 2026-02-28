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

use crate::crypto::secp256k1::{self, PublicKey, RecoverableSignature, SecretKey};
use super::super::address::EthAddress;
use super::types::{Transaction, SignedTransaction};
use super::helpers::eth_sign_message;

pub struct Wallet {
    secret_key: SecretKey,
    public_key: PublicKey,
    address: EthAddress,
}

impl Wallet {
    pub fn generate() -> Self {
        let (sk, pk) = secp256k1::generate_keypair();
        let address = EthAddress::from_public_key(&pk);
        Self {
            secret_key: sk,
            public_key: pk,
            address,
        }
    }

    pub fn from_secret_key(sk: SecretKey) -> Option<Self> {
        let pk = secp256k1::public_key_from_secret(&sk)?;
        let address = EthAddress::from_public_key(&pk);
        Some(Self {
            secret_key: sk,
            public_key: pk,
            address,
        })
    }

    pub fn address(&self) -> &EthAddress {
        &self.address
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn sign_transaction(&self, tx: &Transaction) -> Option<SignedTransaction> {
        tx.sign(&self.secret_key)
    }

    pub fn sign_message(&self, message: &[u8]) -> Option<RecoverableSignature> {
        let prefixed = eth_sign_message(message);
        secp256k1::sign(&self.secret_key, &prefixed)
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        // SAFETY: Zeroing secret key material to prevent leakage after drop.
        for byte in &mut self.secret_key {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}
