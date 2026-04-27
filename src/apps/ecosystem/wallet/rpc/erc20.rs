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
use super::client::EthRpcClient;
use super::transaction::TransactionCall;
use super::types::RpcResult;
use super::utils::hex_to_bytes;
use alloc::vec::Vec;

pub fn balance_of(client: &mut EthRpcClient, token: &str, address: &str) -> RpcResult<u128> {
    let mut data = [0x70, 0xa0, 0x82, 0x31].to_vec();
    let addr_bytes = hex_to_bytes(address)?;
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(&addr_bytes);
    data.extend_from_slice(&padded);
    let result = client.eth_call(&TransactionCall::with_data(token, data), "latest")?;
    if result.len() < 32 {
        return Ok(0);
    }
    let mut be_bytes = [0u8; 16];
    be_bytes.copy_from_slice(&result[16..32]);
    Ok(u128::from_be_bytes(be_bytes))
}

pub fn allowance(
    client: &mut EthRpcClient,
    token: &str,
    owner: &str,
    spender: &str,
) -> RpcResult<u128> {
    let mut data = [0xdd, 0x62, 0xed, 0x3e].to_vec();
    let owner_bytes = hex_to_bytes(owner)?;
    let mut owner_padded = [0u8; 32];
    owner_padded[12..32].copy_from_slice(&owner_bytes);
    data.extend_from_slice(&owner_padded);
    let spender_bytes = hex_to_bytes(spender)?;
    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(&spender_bytes);
    data.extend_from_slice(&spender_padded);
    let result = client.eth_call(&TransactionCall::with_data(token, data), "latest")?;
    if result.len() < 32 {
        return Ok(0);
    }
    let mut be_bytes = [0u8; 16];
    be_bytes.copy_from_slice(&result[16..32]);
    Ok(u128::from_be_bytes(be_bytes))
}

pub fn encode_transfer(to: &str, amount: u128) -> RpcResult<Vec<u8>> {
    let mut data = [0xa9, 0x05, 0x9c, 0xbb].to_vec();
    let to_bytes = hex_to_bytes(to)?;
    let mut to_padded = [0u8; 32];
    to_padded[12..32].copy_from_slice(&to_bytes);
    data.extend_from_slice(&to_padded);
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_padded);
    Ok(data)
}

pub fn encode_approve(spender: &str, amount: u128) -> RpcResult<Vec<u8>> {
    let mut data = [0x09, 0x5e, 0xa7, 0xb3].to_vec();
    let spender_bytes = hex_to_bytes(spender)?;
    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(&spender_bytes);
    data.extend_from_slice(&spender_padded);
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_padded);
    Ok(data)
}
