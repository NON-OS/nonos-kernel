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

use super::types::StakingContract;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcResult};
use crate::apps::ecosystem::wallet::transaction::{
    sign_transaction, SignedTransaction, TransactionRequest,
};

pub fn stake(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    amount: u128,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);
    let data = contract.encode_stake(amount);
    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.staking_address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(150000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);
    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;
    client.send_raw_transaction(&signed.raw)?;
    Ok(signed)
}

pub fn unstake(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    amount: u128,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);
    let data = contract.encode_unstake(amount);
    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.staking_address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(150000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);
    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;
    client.send_raw_transaction(&signed.raw)?;
    Ok(signed)
}

pub fn claim_rewards(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);
    let data = contract.encode_claim();
    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.staking_address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(100000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);
    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;
    client.send_raw_transaction(&signed.raw)?;
    Ok(signed)
}

pub fn approve_staking(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    amount: u128,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);
    let data = contract.encode_approve(amount);
    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.token_address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(60000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);
    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;
    client.send_raw_transaction(&signed.raw)?;
    Ok(signed)
}
