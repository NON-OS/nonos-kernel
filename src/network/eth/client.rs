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
use super::abi;
use super::rpc::{self, RpcError, BASE_RPC};
use super::tx::Tx1559;
use alloc::vec::Vec;

pub fn call(to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>, RpcError> {
    rpc::eth_call(BASE_RPC, to, data)
}

pub fn send_raw_tx(signed: &[u8]) -> Result<[u8; 32], RpcError> {
    rpc::eth_send_raw(BASE_RPC, signed)
}

pub fn get_balance(addr: &[u8; 20]) -> Result<u128, RpcError> {
    rpc::eth_get_balance(BASE_RPC, addr)
}

pub fn get_nonce(addr: &[u8; 20]) -> Result<u64, RpcError> {
    rpc::eth_get_nonce(BASE_RPC, addr)
}

pub fn erc20_balance(token: &[u8; 20], owner: &[u8; 20]) -> Result<u128, RpcError> {
    let data = abi::encode_call("balanceOf(address)", &[owner]);
    let resp = call(token, &data)?;
    abi::decode_u256(&resp, 0).ok_or(RpcError::Parse)
}

pub fn erc20_allowance(
    token: &[u8; 20],
    owner: &[u8; 20],
    spender: &[u8; 20],
) -> Result<u128, RpcError> {
    let data = abi::encode_call("allowance(address,address)", &[owner, spender]);
    let resp = call(token, &data)?;
    abi::decode_u256(&resp, 0).ok_or(RpcError::Parse)
}

pub fn erc20_approve(
    token: &[u8; 20],
    spender: &[u8; 20],
    amount: u128,
    key: &[u8; 32],
) -> Result<[u8; 32], RpcError> {
    let data = abi::encode_call("approve(address,uint256)", &[spender, &abi::encode_u256(amount)]);
    send_tx(token, 0, data, key)
}

pub fn erc20_transfer(
    token: &[u8; 20],
    to: &[u8; 20],
    amount: u128,
    key: &[u8; 32],
) -> Result<[u8; 32], RpcError> {
    let data = abi::encode_call("transfer(address,uint256)", &[to, &abi::encode_u256(amount)]);
    send_tx(token, 0, data, key)
}

pub fn send_tx(
    to: &[u8; 20],
    value: u128,
    data: Vec<u8>,
    key: &[u8; 32],
) -> Result<[u8; 32], RpcError> {
    let addr = crate::crypto::secp256k1::address_from_secret(key);
    let nonce = get_nonce(&addr)?;
    let gas_price = rpc::eth_gas_price(BASE_RPC)?;
    let tx = Tx1559 {
        chain_id: rpc::CHAIN_BASE,
        nonce,
        max_priority: 1_000_000_000,
        max_fee: gas_price as u64 * 2,
        gas_limit: 200_000,
        to: *to,
        value,
        data,
    };
    let signed = tx.sign(key).ok_or(RpcError::Sign)?;
    send_raw_tx(&signed)
}
