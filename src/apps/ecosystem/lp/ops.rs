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


use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcNetwork};
use crate::apps::ecosystem::wallet::state as wallet_state;

use super::contract::compound_rewards;
use super::state;

pub fn auto_compound() -> Result<(), &'static str> {
    let contract = state::get_contract().ok_or("LP not initialized")?;
    let lp_network = state::get_network().ok_or("LP not initialized")?;
    let chain_id = lp_network.chain_id();

    let rpc_network = match chain_id {
        1 => RpcNetwork::Mainnet,
        11155111 => RpcNetwork::Sepolia,
        _ => RpcNetwork::Localhost,
    };

    let account = wallet_state::get_account(0).ok_or("Wallet not initialized")?;
    let address = account.address_hex();
    let secret_key = wallet_state::get_secret_key(0).map_err(|_| "Failed to get secret key")?;

    let mut client = EthRpcClient::new(rpc_network);

    compound_rewards(&mut client, &contract, &address, &secret_key, chain_id)
        .map_err(|_| "Failed to compound rewards")?;

    Ok(())
}
