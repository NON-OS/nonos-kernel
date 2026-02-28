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

use super::super::extended_key::ExtendedPrivateKey;
use super::super::path::DerivationPath;
use crate::crypto::asymmetric::secp256k1::SecretKey;
use crate::crypto::CryptoResult;
use super::master::derive_master_key;
use super::child::derive_child;

pub fn derive_path(
    master: &ExtendedPrivateKey,
    path: &DerivationPath,
) -> CryptoResult<ExtendedPrivateKey> {
    let mut current = master.clone();

    for component in path.components() {
        current = derive_child(&current, component.to_index())?;
    }

    Ok(current)
}

pub fn derive_eth_key(
    seed: &[u8],
    account: u32,
    address_index: u32,
) -> CryptoResult<SecretKey> {
    let master = derive_master_key(seed)?;
    let path = DerivationPath::bip44_eth(account, address_index);
    let derived = derive_path(&master, &path)?;
    Ok(*derived.secret_key())
}
