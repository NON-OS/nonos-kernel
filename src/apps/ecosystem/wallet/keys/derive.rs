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
use super::types::{hex_char, WalletKeys, BIP44_ETH_COIN, BIP44_PURPOSE};
use crate::crypto::application::bip32::{derive_child, derive_master_key};
use crate::crypto::application::bip39::Mnemonic;
use crate::crypto::asymmetric::secp256k1::public_key_from_secret;
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::string::String;

impl WalletKeys {
    pub fn from_seed(seed: &[u8]) -> CryptoResult<Self> {
        let master = derive_master_key(seed)?;
        let purpose = derive_child(&master, 0x80000000 | BIP44_PURPOSE)?;
        let coin = derive_child(&purpose, 0x80000000 | BIP44_ETH_COIN)?;
        let account = derive_child(&coin, 0x80000000)?;
        let change = derive_child(&account, 0)?;
        Ok(Self { master, account_key: change })
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> CryptoResult<Self> {
        Self::from_seed(&mnemonic.to_seed(passphrase))
    }

    pub fn derive_secret_key(&self, index: u32) -> CryptoResult<[u8; 32]> {
        Ok(*derive_child(&self.account_key, index)?.secret_key())
    }

    pub fn derive_address(&self, index: u32) -> CryptoResult<[u8; 20]> {
        let secret_key = self.derive_secret_key(index)?;
        let public_key = public_key_from_secret(&secret_key).ok_or(CryptoError::InvalidInput)?;
        let hash = keccak256(&public_key[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        Ok(address)
    }

    pub fn derive_address_hex(&self, index: u32) -> CryptoResult<String> {
        let address = self.derive_address(index)?;
        let mut hex = String::with_capacity(42);
        hex.push_str("0x");
        for byte in &address {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        Ok(hex)
    }

    pub fn derive_address_checksum(&self, index: u32) -> CryptoResult<String> {
        let address = self.derive_address(index)?;
        let mut hex_chars = [0u8; 40];
        for (i, byte) in address.iter().enumerate() {
            hex_chars[i * 2] = hex_char(byte >> 4);
            hex_chars[i * 2 + 1] = hex_char(byte & 0x0f);
        }
        let addr_hash = keccak256(&hex_chars);
        let mut result = String::with_capacity(42);
        result.push_str("0x");
        for (i, c) in hex_chars.iter().enumerate() {
            let hash_nibble =
                if i % 2 == 0 { addr_hash[i / 2] >> 4 } else { addr_hash[i / 2] & 0x0f };
            if *c >= b'a' && *c <= b'f' && hash_nibble >= 8 {
                result.push((*c as char).to_ascii_uppercase());
            } else {
                result.push(*c as char);
            }
        }
        Ok(result)
    }
}
