// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::types::RpcNetwork;
use alloc::{
    format,
    string::{String, ToString},
};
use spin::RwLock;

static CURRENT_NETWORK: RwLock<RpcNetwork> = RwLock::new(RpcNetwork::Sepolia);

pub fn set_network(network: RpcNetwork) {
    *CURRENT_NETWORK.write() = network;
}
pub fn get_network() -> RpcNetwork {
    *CURRENT_NETWORK.read()
}

pub fn network_name(network: RpcNetwork) -> String {
    match network {
        RpcNetwork::Mainnet => "mainnet".to_string(),
        RpcNetwork::Sepolia => "sepolia".to_string(),
        RpcNetwork::Localhost => "localhost".to_string(),
    }
}

pub fn format_wei_to_eth(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let remainder = (wei % 1_000_000_000_000_000_000) / 1_000_000_000_000_000;
    format!("{}.{:03}", eth, remainder)
}
