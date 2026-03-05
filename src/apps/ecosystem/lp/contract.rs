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
use alloc::vec::Vec;

use super::state::UserPosition;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcResult, TransactionCall};
use crate::apps::ecosystem::wallet::transaction::{sign_transaction, SignedTransaction, TransactionRequest};

const ADD_LIQUIDITY_SELECTOR: [u8; 4] = [0xe8, 0xe3, 0x37, 0x00];
const REMOVE_LIQUIDITY_SELECTOR: [u8; 4] = [0x02, 0x75, 0x1c, 0xec];
const CLAIM_REWARDS_SELECTOR: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];
const COMPOUND_SELECTOR: [u8; 4] = [0xf6, 0x9e, 0x20, 0x46];
const GET_POSITION_SELECTOR: [u8; 4] = [0x99, 0xfb, 0xab, 0x88];
const GET_RESERVES_SELECTOR: [u8; 4] = [0x09, 0x02, 0xf1, 0xac];
const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const PENDING_REWARDS_SELECTOR: [u8; 4] = [0xf4, 0x0f, 0x0f, 0x52];

#[derive(Debug, Clone)]
pub struct LpContract {
    address: [u8; 20],
    address_hex: String,
}

impl LpContract {
    pub fn new(address: &str) -> Self {
        let address_bytes = parse_address(address).unwrap_or([0u8; 20]);

        Self {
            address: address_bytes,
            address_hex: String::from(address),
        }
    }

    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }

    pub fn address_hex(&self) -> &str {
        &self.address_hex
    }

    pub fn encode_add_liquidity(
        &self,
        token0_amount: u128,
        token1_amount: u128,
        min_liquidity: u128,
        deadline: u64,
    ) -> Vec<u8> {
        let mut data = ADD_LIQUIDITY_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(token0_amount));
        data.extend_from_slice(&encode_u256(token1_amount));
        data.extend_from_slice(&encode_u256(min_liquidity));
        data.extend_from_slice(&encode_u256(deadline as u128));
        data
    }

    pub fn encode_remove_liquidity(
        &self,
        lp_amount: u128,
        min_token0: u128,
        min_token1: u128,
        deadline: u64,
    ) -> Vec<u8> {
        let mut data = REMOVE_LIQUIDITY_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(lp_amount));
        data.extend_from_slice(&encode_u256(min_token0));
        data.extend_from_slice(&encode_u256(min_token1));
        data.extend_from_slice(&encode_u256(deadline as u128));
        data
    }

    pub fn encode_claim_rewards(&self) -> Vec<u8> {
        CLAIM_REWARDS_SELECTOR.to_vec()
    }

    pub fn encode_compound(&self) -> Vec<u8> {
        COMPOUND_SELECTOR.to_vec()
    }

    pub fn encode_get_position(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = GET_POSITION_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_get_reserves(&self) -> Vec<u8> {
        GET_RESERVES_SELECTOR.to_vec()
    }

    pub fn encode_total_supply(&self) -> Vec<u8> {
        TOTAL_SUPPLY_SELECTOR.to_vec()
    }

    pub fn encode_balance_of(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = BALANCE_OF_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_pending_rewards(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = PENDING_REWARDS_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }
}

pub fn get_lp_position(
    client: &mut EthRpcClient,
    contract: &LpContract,
    account: &str,
) -> RpcResult<UserPosition> {
    let account_bytes = parse_address(account).ok_or(RpcError::InvalidParams)?;

    let lp_balance = get_lp_balance(client, contract, &account_bytes)?;
    let pending = get_pending_rewards_amount(client, contract, &account_bytes)?;
    let (reserve0, reserve1, _) = get_reserves(client, contract)?;
    let total_supply = get_total_supply(client, contract)?;

    let share = if total_supply > 0 {
        (lp_balance as f64 / total_supply as f64) * 100.0
    } else {
        0.0
    };

    let token0_amount = if total_supply > 0 {
        (lp_balance * reserve0) / total_supply
    } else {
        0
    };

    let token1_amount = if total_supply > 0 {
        (lp_balance * reserve1) / total_supply
    } else {
        0
    };

    Ok(UserPosition {
        lp_tokens: lp_balance,
        token0_amount,
        token1_amount,
        share_percentage: share,
        pending_rewards: pending,
        lock_end_time: 0,
        boosted: false,
    })
}

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

pub fn get_total_supply(
    client: &mut EthRpcClient,
    contract: &LpContract,
) -> RpcResult<u128> {
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

pub fn add_liquidity(
    client: &mut EthRpcClient,
    contract: &LpContract,
    token0_amount: u128,
    token1_amount: u128,
    slippage_basis_points: u16,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);

    let min0 = token0_amount.saturating_mul(10000 - slippage_basis_points as u128) / 10000;
    let min1 = token1_amount.saturating_mul(10000 - slippage_basis_points as u128) / 10000;
    let min_liquidity = min0.min(min1);
    let deadline = crate::time::timestamp_secs() + 1800;

    let data = contract.encode_add_liquidity(
        token0_amount,
        token1_amount,
        min_liquidity,
        deadline,
    );

    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(300000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);

    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;

    client.send_raw_transaction(&signed.raw)?;

    Ok(signed)
}

pub fn remove_liquidity(
    client: &mut EthRpcClient,
    contract: &LpContract,
    lp_amount: u128,
    slippage_basis_points: u16,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);

    let (reserve0, reserve1, _) = get_reserves(client, contract)?;
    let total_supply = get_total_supply(client, contract)?;

    let expected_token0 = if total_supply > 0 {
        (lp_amount * reserve0) / total_supply
    } else {
        0
    };
    let expected_token1 = if total_supply > 0 {
        (lp_amount * reserve1) / total_supply
    } else {
        0
    };

    let min_token0 = (expected_token0 * (10000 - slippage_basis_points as u128)) / 10000;
    let min_token1 = (expected_token1 * (10000 - slippage_basis_points as u128)) / 10000;

    let deadline = crate::time::timestamp_secs() + 1800;

    let data = contract.encode_remove_liquidity(lp_amount, min_token0, min_token1, deadline);

    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(300000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);

    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;

    client.send_raw_transaction(&signed.raw)?;

    Ok(signed)
}

pub fn claim_lp_rewards(
    client: &mut EthRpcClient,
    contract: &LpContract,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);

    let data = contract.encode_claim_rewards();

    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(150000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);

    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;

    client.send_raw_transaction(&signed.raw)?;

    Ok(signed)
}

pub fn compound_rewards(
    client: &mut EthRpcClient,
    contract: &LpContract,
    from_address: &str,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> RpcResult<SignedTransaction> {
    let nonce = client.get_transaction_count(from_address)?;
    let gas_price = client.get_gas_price()?;
    let max_priority_fee = client.get_max_priority_fee().unwrap_or(1_500_000_000);

    let data = contract.encode_compound();

    let tx = TransactionRequest::new_eip1559(chain_id)
        .with_to(contract.address)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(200000)
        .with_eip1559_fees(gas_price + max_priority_fee, max_priority_fee);

    let signed = sign_transaction(&tx, secret_key).map_err(|_| RpcError::InternalError)?;

    client.send_raw_transaction(&signed.raw)?;

    Ok(signed)
}

fn parse_address(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() != 40 {
        return None;
    }

    let mut address = [0u8; 20];
    for i in 0..20 {
        address[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }

    Some(address)
}

fn encode_address(address: &[u8; 20]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(address);
    padded
}

fn encode_u256(value: u128) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    let bytes = value.to_be_bytes();
    encoded[16..32].copy_from_slice(&bytes);
    encoded
}

fn decode_u256(data: &[u8]) -> RpcResult<u128> {
    if data.len() < 32 {
        return Ok(0);
    }

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[16..32]);
    Ok(u128::from_be_bytes(bytes))
}
