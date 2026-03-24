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

use super::state::STAKING_STATE;
use super::constants::*;
use crate::graphics::window::apps::wallet::rpc;
use crate::graphics::window::apps::wallet::state::WALLET_STATE;
use crate::graphics::window::apps::wallet::transaction_parse::parse_eth_to_wei;

pub fn fetch_staking_state() -> Result<(), &'static str> {
    if !rpc::is_rpc_available() { return Err("No network"); }
    let addr = { let s = WALLET_STATE.lock(); s.get_active_account().map(|a| a.address) }.ok_or("No account")?;
    let mut call_data = [0u8; 36]; call_data[0..4].copy_from_slice(&SIG_GET_STAKER_INFO); call_data[16..36].copy_from_slice(&addr);
    if let Ok(result) = rpc::eth_call(&STAKING_SEPOLIA, &call_data) {
        if result.len() >= 192 { let mut s = STAKING_STATE.lock(); s.staked_amount = parse_u256_to_u128(&result[0..32]); s.weighted_amount = parse_u256_to_u128(&result[32..64]); s.boost = parse_u256_to_u32(&result[64..96]); s.pending_rewards = parse_u256_to_u128(&result[128..160]); }
    }
    let mut pool_data = [0u8; 4]; pool_data.copy_from_slice(&SIG_GET_POOL_STATS);
    if let Ok(result) = rpc::eth_call(&STAKING_SEPOLIA, &pool_data) {
        if result.len() >= 192 { let mut s = STAKING_STATE.lock(); s.total_pool_staked = parse_u256_to_u128(&result[0..32]); s.total_weighted = parse_u256_to_u128(&result[32..64]); s.current_apy = parse_u256_to_u32(&result[128..160]); s.genesis_started = true; }
    }
    Ok(())
}

pub fn stake_nox(amount: &str) -> Result<[u8; 32], &'static str> {
    let wei = parse_eth_to_wei(amount).ok_or("Invalid amount")?;
    let mut data = [0u8; 36]; data[0..4].copy_from_slice(&SIG_STAKE);
    encode_u256(&mut data[4..36], wei);
    send_staking_tx(&data)
}

pub fn unstake_nox(amount: &str) -> Result<[u8; 32], &'static str> {
    let wei = parse_eth_to_wei(amount).ok_or("Invalid amount")?;
    let mut data = [0u8; 36]; data[0..4].copy_from_slice(&SIG_UNSTAKE);
    encode_u256(&mut data[4..36], wei);
    send_staking_tx(&data)
}

fn send_staking_tx(data: &[u8]) -> Result<[u8; 32], &'static str> {
    use crate::graphics::window::apps::wallet::transaction_parse::derive_signing_key;
    use crate::graphics::window::apps::wallet::transaction_sign::build_and_sign_contract_tx;
    use crate::graphics::window::apps::wallet::network::chain_id;
    let s = WALLET_STATE.lock();
    if !s.unlocked { return Err("Wallet locked"); }
    let mk = s.master_key.ok_or("No master key")?;
    let (from, idx) = s.get_active_account().map(|a| (a.address, a.index)).ok_or("No account")?;
    drop(s);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx = build_and_sign_contract_tx(&STAKING_SEPOLIA, 0, data, nonce, gp, 150000, chain_id(), &sk).map_err(|_| "Build tx failed")?;
    rpc::send_raw_transaction(&tx).map_err(|_| "Tx broadcast failed")
}

fn parse_u256_to_u128(data: &[u8]) -> u128 { if data.len() < 32 { return 0; } let mut r = 0u128; for i in 16..32 { r = (r << 8) | data[i] as u128; } r }
fn parse_u256_to_u32(data: &[u8]) -> u32 { if data.len() < 32 { return 0; } let mut r = 0u32; for i in 28..32 { r = (r << 8) | data[i] as u32; } r }
fn encode_u256(buf: &mut [u8], val: u128) { for i in 0..16 { buf[i] = 0; } for i in 0..16 { buf[16 + 15 - i] = ((val >> (i * 8)) & 0xff) as u8; } }
