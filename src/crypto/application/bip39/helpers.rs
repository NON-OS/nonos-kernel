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
use crate::crypto::CryptoResult;

use super::types::MnemonicStrength;
use super::mnemonic::Mnemonic;

pub fn validate_mnemonic(phrase: &str) -> bool {
    Mnemonic::from_phrase(phrase).is_ok()
}

pub fn generate_mnemonic_12() -> CryptoResult<String> {
    let m = Mnemonic::generate(MnemonicStrength::Words12)?;
    Ok(m.to_phrase())
}

pub fn generate_mnemonic_24() -> CryptoResult<String> {
    let m = Mnemonic::generate(MnemonicStrength::Words24)?;
    Ok(m.to_phrase())
}

pub fn generate_mnemonic(word_count: usize) -> CryptoResult<String> {
    let strength = match word_count {
        12 => MnemonicStrength::Words12,
        15 => MnemonicStrength::Words15,
        18 => MnemonicStrength::Words18,
        21 => MnemonicStrength::Words21,
        24 => MnemonicStrength::Words24,
        _ => return Err(crate::crypto::CryptoError::InvalidLength),
    };
    let m = Mnemonic::generate(strength)?;
    Ok(m.to_phrase())
}

pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> CryptoResult<[u8; 64]> {
    let m = Mnemonic::from_phrase(phrase)?;
    Ok(m.to_seed(passphrase))
}
