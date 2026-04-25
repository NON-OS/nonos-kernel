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
use super::types::WalletKeys;
use crate::crypto::application::bip39::Mnemonic;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::string::String;

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
