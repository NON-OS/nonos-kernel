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

//! Staking contract interactions.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcNetwork, RpcResult, TransactionCall};
use crate::apps::ecosystem::wallet::transaction::{sign_transaction, SignedTransaction, TransactionRequest};

const STAKE_SELECTOR: [u8; 4] = [0xa6, 0x94, 0xfc, 0x3a];
const UNSTAKE_SELECTOR: [u8; 4] = [0x2e, 0x17, 0xde, 0x78];
const CLAIM_SELECTOR: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];
const STAKED_AMOUNT_SELECTOR: [u8; 4] = [0x37, 0x3d, 0x6b, 0x32];
const PENDING_REWARDS_SELECTOR: [u8; 4] = [0xf4, 0x0f, 0x0f, 0x52];
const TOTAL_STAKED_SELECTOR: [u8; 4] = [0x81, 0x7b, 0x1c, 0xd2];
const APY_SELECTOR: [u8; 4] = [0x2d, 0x33, 0x9a, 0x5f];
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

#[derive(Debug, Clone)]
pub struct StakingContract {
    staking_address: [u8; 20],
    token_address: [u8; 20],
    staking_address_hex: String,
    token_address_hex: String,
}

impl StakingContract {
    pub fn new(staking_address: &str, token_address: &str) -> Self {
        let staking_bytes = parse_address(staking_address).unwrap_or([0u8; 20]);
        let token_bytes = parse_address(token_address).unwrap_or([0u8; 20]);

        Self {
            staking_address: staking_bytes,
            token_address: token_bytes,
            staking_address_hex: String::from(staking_address),
            token_address_hex: String::from(token_address),
        }
    }

    pub fn for_network(network: RpcNetwork) -> Option<Self> {
        match network {
            RpcNetwork::Mainnet => Some(Self::new(
                "0x00000000219ab540356cBB839Cbe05303d7705Fa",
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            )),
            RpcNetwork::Sepolia => Some(Self::new(
                "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",
                "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",
            )),
            RpcNetwork::Localhost => None,
        }
    }

    pub fn staking_address(&self) -> &[u8; 20] {
        &self.staking_address
    }

    pub fn token_address(&self) -> &[u8; 20] {
        &self.token_address
    }

    pub fn token_address_hex(&self) -> &str {
        &self.token_address_hex
    }

    pub fn encode_stake(&self, amount: u128) -> Vec<u8> {
        let mut data = STAKE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(amount));
        data
    }

    pub fn encode_unstake(&self, amount: u128) -> Vec<u8> {
        let mut data = UNSTAKE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(amount));
        data
    }

    pub fn encode_claim(&self) -> Vec<u8> {
        CLAIM_SELECTOR.to_vec()
    }

    pub fn encode_staked_amount(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = STAKED_AMOUNT_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_pending_rewards(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = PENDING_REWARDS_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_total_staked(&self) -> Vec<u8> {
        TOTAL_STAKED_SELECTOR.to_vec()
    }

    pub fn encode_apy(&self) -> Vec<u8> {
        APY_SELECTOR.to_vec()
    }

    pub fn encode_approve(&self, amount: u128) -> Vec<u8> {
        let mut data = APPROVE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(&self.staking_address));
        data.extend_from_slice(&encode_u256(amount));
        data
    }
}

pub fn get_staked_amount(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    account: &str,
) -> RpcResult<u128> {
    let account_bytes = parse_address(account).ok_or(RpcError::InvalidParams)?;
    let data = contract.encode_staked_amount(&account_bytes);

    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    let result = client.eth_call(&call, "latest")?;

    decode_u256(&result)
}

pub fn get_pending_rewards(
    client: &mut EthRpcClient,
    contract: &StakingContract,
    account: &str,
) -> RpcResult<u128> {
    let account_bytes = parse_address(account).ok_or(RpcError::InvalidParams)?;
    let data = contract.encode_pending_rewards(&account_bytes);

    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    let result = client.eth_call(&call, "latest")?;

    decode_u256(&result)
}

pub fn get_total_staked(
    client: &mut EthRpcClient,
    contract: &StakingContract,
) -> RpcResult<u128> {
    let data = contract.encode_total_staked();

    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    let result = client.eth_call(&call, "latest")?;

    decode_u256(&result)
}

pub fn get_current_apy(
    client: &mut EthRpcClient,
    contract: &StakingContract,
) -> RpcResult<u64> {
    let data = contract.encode_apy();

    let call = TransactionCall::with_data(&contract.staking_address_hex, data);
    let result = client.eth_call(&call, "latest")?;

    let value = decode_u256(&result)?;
    Ok(value as u64)
}

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
