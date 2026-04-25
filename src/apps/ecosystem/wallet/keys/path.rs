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
use super::types::{BIP44_ETH_COIN, BIP44_PURPOSE};
use crate::crypto::application::bip32::{
    derive_child, derive_master_key, DerivationPath, PathComponent,
};
use crate::crypto::CryptoResult;

pub fn derive_from_path(seed: &[u8], path: &DerivationPath) -> CryptoResult<[u8; 32]> {
    let master = derive_master_key(seed)?;
    let mut current = master;
    for component in path.components() {
        current = derive_child(&current, component.to_index())?;
    }
    Ok(*current.secret_key())
}

pub fn derive_eth_account(seed: &[u8], account: u32, index: u32) -> CryptoResult<[u8; 32]> {
    derive_from_path(seed, &eth_derivation_path(account, index))
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
