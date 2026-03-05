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

use alloc::string::String;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::crypto::application::bip32::{derive_master_key, derive_child, DerivationPath, ExtendedPrivateKey, PathComponent};
use crate::crypto::application::bip39::Mnemonic;
use crate::crypto::asymmetric::secp256k1::public_key_from_secret;
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};

const BIP44_PURPOSE: u32 = 44;
const BIP44_ETH_COIN: u32 = 60;

#[derive(Clone)]
pub struct WalletKeys {
    master: ExtendedPrivateKey,
    account_key: ExtendedPrivateKey,
}

impl WalletKeys {
    pub fn from_seed(seed: &[u8]) -> CryptoResult<Self> {
        let master = derive_master_key(seed)?;

        let purpose = derive_child(&master, 0x80000000 | BIP44_PURPOSE)?;
        let coin = derive_child(&purpose, 0x80000000 | BIP44_ETH_COIN)?;
        let account = derive_child(&coin, 0x80000000)?;
        let change = derive_child(&account, 0)?;

        Ok(Self {
            master,
            account_key: change,
        })
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> CryptoResult<Self> {
        let seed = mnemonic.to_seed(passphrase);
        Self::from_seed(&seed)
    }

    pub fn derive_secret_key(&self, index: u32) -> CryptoResult<[u8; 32]> {
        let child = derive_child(&self.account_key, index)?;
        Ok(*child.secret_key())
    }

    pub fn derive_address(&self, index: u32) -> CryptoResult<[u8; 20]> {
        let secret_key = self.derive_secret_key(index)?;
        let public_key = public_key_from_secret(&secret_key)
            .ok_or(CryptoError::InvalidInput)?;

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
            let high = byte >> 4;
            let low = byte & 0x0f;
            hex_chars[i * 2] = hex_char(high);
            hex_chars[i * 2 + 1] = hex_char(low);
        }

        let addr_hash = keccak256(&hex_chars);

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_chars.iter().enumerate() {
            let hash_byte = addr_hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if *c >= b'a' && *c <= b'f' && hash_nibble >= 8 {
                result.push((*c as char).to_ascii_uppercase());
            } else {
                result.push(*c as char);
            }
        }

        Ok(result)
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(&mut self.master as *mut ExtendedPrivateKey, core::mem::zeroed());
            ptr::write_volatile(&mut self.account_key as *mut ExtendedPrivateKey, core::mem::zeroed());
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn hex_char(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

pub fn generate_wallet(word_count: usize) -> CryptoResult<(String, WalletKeys)> {
    let mnemonic = match word_count {
        12 => Mnemonic::generate_12()?,
        24 => Mnemonic::generate_24()?,
        _ => return Err(CryptoError::InvalidLength),
    };

    let phrase = mnemonic.to_phrase();
    let keys = WalletKeys::from_mnemonic(&mnemonic, "")?;

    Ok((phrase, keys))
}

pub fn import_wallet(phrase: &str, passphrase: &str) -> CryptoResult<WalletKeys> {
    let mnemonic = Mnemonic::from_phrase(phrase)?;
    WalletKeys::from_mnemonic(&mnemonic, passphrase)
}

pub fn derive_account(keys: &WalletKeys, index: u32) -> CryptoResult<([u8; 32], [u8; 20])> {
    let secret_key = keys.derive_secret_key(index)?;
    let address = keys.derive_address(index)?;
    Ok((secret_key, address))
}

pub fn address_to_hex(address: &[u8; 20]) -> String {
    let mut hex = String::with_capacity(42);
    hex.push_str("0x");
    for byte in address {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    hex
}

pub fn address_from_hex(hex: &str) -> CryptoResult<[u8; 20]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() != 40 {
        return Err(CryptoError::InvalidLength);
    }

    let mut address = [0u8; 20];
    for i in 0..20 {
        let byte_hex = &hex[i * 2..i * 2 + 2];
        address[i] = u8::from_str_radix(byte_hex, 16)
            .map_err(|_| CryptoError::InvalidInput)?;
    }

    Ok(address)
}

pub fn checksum_address(address: &[u8; 20]) -> String {
    let mut hex_chars = [0u8; 40];
    for (i, byte) in address.iter().enumerate() {
        let high = byte >> 4;
        let low = byte & 0x0f;
        hex_chars[i * 2] = hex_char(high);
        hex_chars[i * 2 + 1] = hex_char(low);
    }

    let addr_hash = keccak256(&hex_chars);

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_chars.iter().enumerate() {
        let hash_byte = addr_hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };

        if *c >= b'a' && *c <= b'f' && hash_nibble >= 8 {
            result.push((*c as char).to_ascii_uppercase());
        } else {
            result.push(*c as char);
        }
    }

    result
}

pub fn validate_address(address: &str) -> bool {
    let address = match address.strip_prefix("0x") {
        Some(a) => a,
        None => return false,
    };

    if address.len() != 40 {
        return false;
    }

    address.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn validate_checksum_address(address: &str) -> bool {
    if !address.starts_with("0x") || address.len() != 42 {
        return false;
    }

    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    let lower = hex_part.to_ascii_lowercase();
    let mut hex_bytes = [0u8; 40];
    for (i, c) in lower.chars().enumerate() {
        hex_bytes[i] = c as u8;
    }

    let hash = keccak256(&hex_bytes);

    for (i, c) in hex_part.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };

        let expected_upper = c.is_ascii_alphabetic() && hash_nibble >= 8;
        let is_upper = c.is_ascii_uppercase();

        if c.is_ascii_alphabetic() && expected_upper != is_upper {
            return false;
        }
    }

    true
}

pub fn derive_from_path(seed: &[u8], path: &DerivationPath) -> CryptoResult<[u8; 32]> {
    let master = derive_master_key(seed)?;
    let mut current = master;
    for component in path.components() {
        current = derive_child(&current, component.to_index())?;
    }
    Ok(*current.secret_key())
}

pub fn derive_eth_account(seed: &[u8], account: u32, index: u32) -> CryptoResult<[u8; 32]> {
    let path = eth_derivation_path(account, index);
    derive_from_path(seed, &path)
}

pub fn eth_derivation_path(account: u32, index: u32) -> DerivationPath {
    DerivationPath::from_components(alloc::vec![
        PathComponent::hardened(BIP44_PURPOSE),
        PathComponent::hardened(BIP44_ETH_COIN),
        PathComponent::hardened(account),
        PathComponent::normal(0),
        PathComponent::normal(index),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wallet() {
        let (phrase, keys) = generate_wallet(12).unwrap();
        let words: alloc::vec::Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);

        let address = keys.derive_address(0).unwrap();
        assert_ne!(address, [0u8; 20]);
    }

    #[test]
    fn test_import_wallet() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = import_wallet(phrase, "").unwrap();

        let address = keys.derive_address_hex(0).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_address_validation() {
        assert!(validate_address("0x742d35cc6634c0532925a3b844bc454e4438f44e"));
        assert!(validate_address("0x742D35CC6634C0532925A3B844BC454E4438F44E"));
        assert!(!validate_address("0x742d35cc"));
        assert!(!validate_address("742d35cc6634c0532925a3b844bc454e4438f44e"));
    }
}
