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

mod wordlist;
mod types;
mod mnemonic;
mod helpers;

pub use wordlist::ENGLISH_WORDLIST;
pub use types::MnemonicStrength;
pub use mnemonic::Mnemonic;
pub use helpers::{validate_mnemonic, generate_mnemonic_12, generate_mnemonic_24, generate_mnemonic, mnemonic_to_seed};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_12() {
        let m = Mnemonic::generate(MnemonicStrength::Words12).unwrap();
        assert_eq!(m.word_count(), 12);
        let phrase = m.to_phrase();
        assert!(Mnemonic::from_phrase(&phrase).is_ok());
    }

    #[test]
    fn test_mnemonic_generation_24() {
        let m = Mnemonic::generate(MnemonicStrength::Words24).unwrap();
        assert_eq!(m.word_count(), 24);
        let phrase = m.to_phrase();
        assert!(Mnemonic::from_phrase(&phrase).is_ok());
    }

    #[test]
    fn test_known_vector() {
        let entropy = [0x00u8; 16];
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = m.to_phrase();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_seed_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = Mnemonic::from_phrase(phrase).unwrap();
        let seed = m.to_seed("TREZOR");
        let expected_prefix = [0xc5, 0x52, 0x57, 0xc3];
        assert_eq!(&seed[0..4], &expected_prefix);
    }

    #[test]
    fn test_invalid_checksum() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }

    #[test]
    fn test_invalid_word() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }
}
