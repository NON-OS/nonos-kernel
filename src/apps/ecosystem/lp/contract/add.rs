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

use super::types::LpContract;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcResult};
use crate::apps::ecosystem::wallet::transaction::{
    sign_transaction, SignedTransaction, TransactionRequest,
};

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
    let data = contract.encode_add_liquidity(token0_amount, token1_amount, min_liquidity, deadline);
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
