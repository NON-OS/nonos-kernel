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

use super::helpers::decode_u256;
use super::types::LpContract;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcResult, TransactionCall};

pub fn get_reserves(
    client: &mut EthRpcClient,
    contract: &LpContract,
) -> RpcResult<(u128, u128, u64)> {
    let data = contract.encode_get_reserves();
    let call = TransactionCall::with_data(&contract.address_hex, data);
    let result = client.eth_call(&call, "latest")?;
    if result.len() < 96 {
        return Ok((0, 0, 0));
    }
    let reserve0 = decode_u256(&result[0..32])?;
    let reserve1 = decode_u256(&result[32..64])?;
    let timestamp = decode_u256(&result[64..96])? as u64;
    Ok((reserve0, reserve1, timestamp))
}

pub fn get_total_supply(client: &mut EthRpcClient, contract: &LpContract) -> RpcResult<u128> {
    let data = contract.encode_total_supply();
    let call = TransactionCall::with_data(&contract.address_hex, data);
    let result = client.eth_call(&call, "latest")?;
    decode_u256(&result)
}

pub fn get_lp_balance(
    client: &mut EthRpcClient,
    contract: &LpContract,
    account: &[u8; 20],
) -> RpcResult<u128> {
    let data = contract.encode_balance_of(account);
    let call = TransactionCall::with_data(&contract.address_hex, data);
    let result = client.eth_call(&call, "latest")?;
    decode_u256(&result)
}

pub fn get_pending_rewards_amount(
    client: &mut EthRpcClient,
    contract: &LpContract,
    account: &[u8; 20],
) -> RpcResult<u128> {
    let data = contract.encode_pending_rewards(account);
    let call = TransactionCall::with_data(&contract.address_hex, data);
    let result = client.eth_call(&call, "latest")?;
    decode_u256(&result)
}
