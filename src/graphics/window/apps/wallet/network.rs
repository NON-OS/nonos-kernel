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

use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkId {
    Mainnet,
    Sepolia,
}

impl NetworkId {
    pub(crate) fn chain_id(&self) -> u64 {
        match self {
            NetworkId::Mainnet => 1,
            NetworkId::Sepolia => 11155111,
        }
    }

    pub(crate) fn name(&self) -> &'static [u8] {
        match self {
            NetworkId::Mainnet => b"Ethereum",
            NetworkId::Sepolia => b"Sepolia",
        }
    }

    pub(crate) fn nox_contract(&self) -> [u8; 20] {
        match self {
            NetworkId::Mainnet => [
                0x0a, 0x26, 0xc8, 0x0b, 0xe4, 0xe0, 0x60, 0xe6, 0x88, 0xd7,
                0xc2, 0x3a, 0xdd, 0xb9, 0x2c, 0xbb, 0x5d, 0x2c, 0x9e, 0xca,
            ],
            NetworkId::Sepolia => [
                0xc8, 0x77, 0x99, 0xc4, 0x51, 0x7d, 0xcd, 0xfc, 0x65, 0xbf,
                0xef, 0xa3, 0xbe, 0x64, 0xbe, 0xb8, 0x96, 0x68, 0xc6, 0x6c,
            ],
        }
    }
}

static CURRENT_NETWORK: AtomicU8 = AtomicU8::new(1);

pub(crate) fn get_network() -> NetworkId {
    match CURRENT_NETWORK.load(Ordering::SeqCst) {
        1 => NetworkId::Mainnet,
        _ => NetworkId::Sepolia,
    }
}

pub(crate) fn toggle_network() {
    let current = CURRENT_NETWORK.load(Ordering::SeqCst);
    let next = if current == 0 { 1 } else { 0 };
    CURRENT_NETWORK.store(next, Ordering::SeqCst);
}

pub(crate) fn chain_id() -> u64 {
    get_network().chain_id()
}

pub(crate) fn nox_contract() -> [u8; 20] {
    get_network().nox_contract()
}
