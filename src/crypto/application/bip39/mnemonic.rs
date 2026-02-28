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
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::crypto::hash::sha256;
use crate::crypto::util::hmac::pbkdf2_hmac_sha512;
use crate::crypto::random;
use crate::crypto::CryptoResult;

use super::types::MnemonicStrength;
use super::wordlist::ENGLISH_WORDLIST;

pub struct Mnemonic {
    entropy: Vec<u8>,
    words: Vec<u16>,
}

impl Mnemonic {
    pub fn generate(strength: MnemonicStrength) -> CryptoResult<Self> {
        let entropy_bytes = strength.entropy_bits() / 8;
        let mut entropy = alloc::vec![0u8; entropy_bytes];

        random::get_bytes(&mut entropy)?;

        Self::from_entropy(&entropy)
    }

    pub fn generate_12() -> CryptoResult<Self> {
        Self::generate(MnemonicStrength::Words12)
    }

    pub fn generate_24() -> CryptoResult<Self> {
        Self::generate(MnemonicStrength::Words24)
    }

    pub fn from_entropy(entropy: &[u8]) -> CryptoResult<Self> {
        let bit_len = entropy.len() * 8;

        if bit_len != 128 && bit_len != 160 && bit_len != 192 && bit_len != 224 && bit_len != 256 {
            return Err(crate::crypto::CryptoError::InvalidLength);
        }

        let checksum_bits = bit_len / 32;
        let hash = sha256(entropy);
        let checksum_byte = hash[0];

        let total_bits = bit_len + checksum_bits;
        let word_count = total_bits / 11;

        let mut bits = Vec::with_capacity(total_bits);

        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }

        for i in (0..checksum_bits).rev() {
            bits.push((checksum_byte >> (7 - i)) & 1);
        }

        let mut words = Vec::with_capacity(word_count);
        for chunk in bits.chunks(11) {
            let mut index: u16 = 0;
            for &bit in chunk {
                index = (index << 1) | (bit as u16);
            }
            words.push(index);
        }

        Ok(Self {
            entropy: entropy.to_vec(),
            words,
        })
    }

    pub fn from_phrase(phrase: &str) -> CryptoResult<Self> {
        let word_strs: Vec<&str> = phrase.split_whitespace().collect();

        let word_count = word_strs.len();
        if word_count != 12 && word_count != 15 && word_count != 18 && word_count != 21 && word_count != 24 {
            return Err(crate::crypto::CryptoError::InvalidLength);
        }

        let mut word_indices = Vec::with_capacity(word_count);
        for word in &word_strs {
            let word_lower = word.to_lowercase();
            let index = ENGLISH_WORDLIST
                .iter()
                .position(|&w| w == word_lower.as_str())
                .ok_or(crate::crypto::CryptoError::InvalidInput)?;
            word_indices.push(index as u16);
        }

        let total_bits = word_count * 11;
        let checksum_bits = word_count / 3;
        let entropy_bits = total_bits - checksum_bits;

        let mut bits = Vec::with_capacity(total_bits);
        for &index in &word_indices {
            for i in (0..11).rev() {
                bits.push(((index >> i) & 1) as u8);
            }
        }

        let entropy_bytes = entropy_bits / 8;
        let mut entropy = alloc::vec![0u8; entropy_bytes];
        for (i, byte) in entropy.iter_mut().enumerate() {
            for j in 0..8 {
                *byte |= bits[i * 8 + j] << (7 - j);
            }
        }

        let hash = sha256(&entropy);
        let expected_checksum = hash[0] >> (8 - checksum_bits);
        let mut actual_checksum: u8 = 0;
        for i in 0..checksum_bits {
            actual_checksum |= bits[entropy_bits + i] << (checksum_bits - 1 - i);
        }

        if expected_checksum != actual_checksum {
            return Err(crate::crypto::CryptoError::VerificationFailed);
        }

        Ok(Self {
            entropy,
            words: word_indices,
        })
    }

    pub fn to_phrase(&self) -> String {
        let mut phrase = String::with_capacity(self.words.len() * 9);
        for (i, &index) in self.words.iter().enumerate() {
            if i > 0 {
                phrase.push(' ');
            }
            phrase.push_str(ENGLISH_WORDLIST[index as usize]);
        }
        phrase
    }

    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic_bytes = self.to_phrase();
        let salt = alloc::format!("mnemonic{}", passphrase);

        let derived = pbkdf2_hmac_sha512(mnemonic_bytes.as_bytes(), salt.as_bytes(), 2048, 64);

        let mut seed = [0u8; 64];
        seed.copy_from_slice(&derived);
        seed
    }

    pub fn word_count(&self) -> usize {
        self.words.len()
    }

    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        for byte in self.entropy.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        for word in self.words.iter_mut() {
            unsafe { ptr::write_volatile(word, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
