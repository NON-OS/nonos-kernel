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

use super::super::state::UserPosition;
use super::helpers::parse_address;
use super::query::{get_lp_balance, get_pending_rewards_amount, get_reserves, get_total_supply};
use super::types::LpContract;
use crate::apps::ecosystem::wallet::rpc::{EthRpcClient, RpcError, RpcResult};

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
    let share =
        if total_supply > 0 { (lp_balance as f64 / total_supply as f64) * 100.0 } else { 0.0 };
    let token0_amount = if total_supply > 0 { (lp_balance * reserve0) / total_supply } else { 0 };
    let token1_amount = if total_supply > 0 { (lp_balance * reserve1) / total_supply } else { 0 };
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
