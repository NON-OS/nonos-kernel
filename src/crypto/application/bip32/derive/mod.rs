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

pub mod constants;
pub mod master;
pub mod child;
pub mod path;
pub mod validate;
pub mod scalar_math;

pub use master::derive_master_key;
pub use child::derive_child;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::application::bip32::extended_key::HARDENED_OFFSET;
    use crate::crypto::application::bip32::path::DerivationPath;
    use crate::crypto::application::bip39::Mnemonic;

    #[test]
    fn test_derive_master_key() {
        let seed = [0u8; 64];
        let master = derive_master_key(&seed).unwrap();
        assert_eq!(master.depth(), 0);
    }

    #[test]
    fn test_derive_child_hardened() {
        let seed = [0u8; 64];
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child(&master, HARDENED_OFFSET).unwrap();
        assert_eq!(child.depth(), 1);
        assert!(child.is_hardened());
    }

    #[test]
    fn test_bip44_eth_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed("");

        let master = derive_master_key(&seed).unwrap();
        let path = DerivationPath::bip44_eth(0, 0);
        let derived = derive_path(&master, &path).unwrap();

        assert_eq!(derived.depth(), 5);
    }
}
