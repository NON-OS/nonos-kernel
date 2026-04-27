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

use super::types::TransactionRequest;

pub fn encode_eth_transfer(to: &[u8; 20], value_wei: u128) -> TransactionRequest {
    TransactionRequest::new_eip1559(1).with_to(*to).with_value(value_wei).with_gas_limit(21000)
}

pub fn encode_erc20_transfer(token: &[u8; 20], to: &[u8; 20], amount: u128) -> TransactionRequest {
    let mut data = [0xa9, 0x05, 0x9c, 0xbb].to_vec();
    let mut to_padded = [0u8; 32];
    to_padded[12..32].copy_from_slice(to);
    data.extend_from_slice(&to_padded);
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_padded);
    TransactionRequest::new_eip1559(1).with_to(*token).with_data(data).with_gas_limit(65000)
}

pub fn encode_erc20_approve(
    token: &[u8; 20],
    spender: &[u8; 20],
    amount: u128,
) -> TransactionRequest {
    let mut data = [0x09, 0x5e, 0xa7, 0xb3].to_vec();
    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(spender);
    data.extend_from_slice(&spender_padded);
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_padded);
    TransactionRequest::new_eip1559(1).with_to(*token).with_data(data).with_gas_limit(50000)
}
