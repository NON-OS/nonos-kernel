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

use super::helpers::{decode_u256, parse_address};
use super::types::StakingContract;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcResult, TransactionCall};

pub fn get_staked_amount(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    account: &str,
) -> RpcResult<u128> {
    let account_bytes = parse_address(account).ok_or(RpcError::InvalidParams)?;
    let data = contract.encode_staked_amount(&account_bytes);
    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    decode_u256(&client.eth_call(&call, "latest")?)
}

pub fn get_pending_rewards(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    account: &str,
) -> RpcResult<u128> {
    let account_bytes = parse_address(account).ok_or(RpcError::InvalidParams)?;
    let data = contract.encode_pending_rewards(&account_bytes);
    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    decode_u256(&client.eth_call(&call, "latest")?)
}

pub fn get_total_staked(client: &mut EthRpcClient, contract: &StakingContract) -> RpcResult<u128> {
    let data = contract.encode_total_staked();
    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    decode_u256(&client.eth_call(&call, "latest")?)
}

pub fn get_current_apy(client: &mut EthRpcClient, contract: &StakingContract) -> RpcResult<u64> {
    let data = contract.encode_apy();
    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    Ok(decode_u256(&client.eth_call(&call, "latest")?)? as u64)
}
