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
use super::helpers::parse_address;
use crate::apps::ecosystem::wallet::rpc::RpcNetwork;

#[derive(Debug, Clone)]
pub struct StakingContract {
    pub(super) staking_address: [u8; 20],
    pub(super) token_address: [u8; 20],
    pub(super) staking_address_hex: String,
    pub(super) token_address_hex: String,
}

impl StakingContract {
    pub fn new(staking_address: &str, token_address: &str) -> Self {
        let staking_bytes = parse_address(staking_address).unwrap_or([0u8; 20]);
        let token_bytes = parse_address(token_address).unwrap_or([0u8; 20]);
        Self { staking_address: staking_bytes, token_address: token_bytes, staking_address_hex: String::from(staking_address), token_address_hex: String::from(token_address) }
    }

    pub fn for_network(network: RpcNetwork) -> Option<Self> {
        match network {
            RpcNetwork::Mainnet => Some(Self::new("0xa94d6009790Ba13597A1E1b7cF4e1531eA513613", "0x0a26c80Be4E060e688d7C23aDdB92cBb5D2C9eCA")),
            RpcNetwork::Sepolia => Some(Self::new("0x7c34956eb5e92460307846D754dD4d1a2400B652", "0xC87799c4517Dcdfc65bfefa3Be64Beb89668c66c")),
            RpcNetwork::Localhost => None,
        }
    }

    pub fn staking_address(&self) -> &[u8; 20] { &self.staking_address }
    pub fn token_address(&self) -> &[u8; 20] { &self.token_address }
    pub fn token_address_hex(&self) -> &str { &self.token_address_hex }
}
