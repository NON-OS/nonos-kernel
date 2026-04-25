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

use super::constants::*;
use super::state::STAKING_STATE;
use crate::graphics::window::apps::wallet::rpc;
use crate::graphics::window::apps::wallet::state::WALLET_STATE;
use crate::graphics::window::apps::wallet::transaction_parse::parse_eth_to_wei;

pub(super) fn fetch_staking_state() -> Result<(), &'static str> {
    if !rpc::is_rpc_available() {
        return Err("No network");
    }
    let addr = {
        let s = WALLET_STATE.lock();
        s.get_active_account().map(|a| a.address)
    }
    .ok_or("No account")?;
    let mut nft_data = [0u8; 36];
    nft_data[0..4].copy_from_slice(&SIG_BALANCE_OF);
    nft_data[16..36].copy_from_slice(&addr);
    if let Ok(result) = rpc::eth_call(&ZSP_MAINNET, &nft_data) {
        if result.len() >= 32 {
            STAKING_STATE.lock().nft_count = parse_u256_to_u32(&result[0..32]).min(255) as u8;
        }
    }
    let mut call_data = [0u8; 36];
    call_data[0..4].copy_from_slice(&SIG_GET_STAKER_INFO);
    call_data[16..36].copy_from_slice(&addr);
    if let Ok(result) = rpc::eth_call(&STAKING_MAINNET, &call_data) {
        if result.len() >= 160 {
            let mut s = STAKING_STATE.lock();
            s.staked_amount = parse_u256_to_u128(&result[0..32]);
            s.weighted_amount = parse_u256_to_u128(&result[32..64]);
            s.pending_rewards = parse_u256_to_u128(&result[96..128]);
            s.boost = parse_u256_to_u32(&result[128..160]);
        }
    }
    let mut pool_data = [0u8; 4];
    pool_data.copy_from_slice(&SIG_GET_POOL_STATS);
    if let Ok(result) = rpc::eth_call(&STAKING_MAINNET, &pool_data) {
        if result.len() >= 128 {
            let mut s = STAKING_STATE.lock();
            s.total_pool_staked = parse_u256_to_u128(&result[0..32]);
            s.total_weighted = parse_u256_to_u128(&result[32..64]);
            s.emission_rate = parse_u256_to_u128(&result[64..96]);
            s.current_apy = parse_u256_to_u32(&result[96..128]);
            s.genesis_started = true;
        }
    }
    let mut allow_data = [0u8; 68];
    allow_data[0..4].copy_from_slice(&SIG_ALLOWANCE);
    allow_data[16..36].copy_from_slice(&addr);
    allow_data[48..68].copy_from_slice(&STAKING_MAINNET);
    if let Ok(result) = rpc::eth_call(&NOX_MAINNET, &allow_data) {
        if result.len() >= 32 {
            STAKING_STATE.lock().allowance = parse_u256_to_u128(&result[0..32]);
        }
    }
    Ok(())
}

pub(super) fn stake_nox(amount: &str) -> Result<[u8; 32], &'static str> {
    let wei = parse_eth_to_wei(amount).ok_or("Invalid amount")?;
    let allowance = { STAKING_STATE.lock().allowance };
    if allowance < wei {
        approve_nox()?;
    }
    let mut data = [0u8; 36];
    data[0..4].copy_from_slice(&SIG_STAKE);
    encode_u256(&mut data[4..36], wei);
    send_staking_tx(&data)
}

pub(super) fn approve_nox() -> Result<[u8; 32], &'static str> {
    use crate::graphics::window::apps::wallet::transaction_parse::derive_signing_key;
    use crate::graphics::window::apps::wallet::transaction_sign::build_and_sign_contract_tx;
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err("Wallet locked");
    }
    let mk = s.master_key.ok_or("No master key")?;
    let (from, idx) = s.get_active_account().map(|a| (a.address, a.index)).ok_or("No account")?;
    drop(s);
    let mut data = [0u8; 68];
    data[0..4].copy_from_slice(&SIG_APPROVE);
    data[16..36].copy_from_slice(&STAKING_MAINNET);
    for i in 4..36 {
        data[32 + i] = 0xff;
    }
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx = build_and_sign_contract_tx(&NOX_MAINNET, 0, &data, nonce, gp, 60000, 1, &sk)
        .map_err(|_| "Build tx failed")?;
    rpc::send_raw_transaction(&tx).map_err(|_| "Approve failed")?;
    STAKING_STATE.lock().allowance = u128::MAX;
    Ok([0u8; 32])
}

pub(super) fn unstake_nox(amount: &str) -> Result<[u8; 32], &'static str> {
    let wei = parse_eth_to_wei(amount).ok_or("Invalid amount")?;
    let mut data = [0u8; 36];
    data[0..4].copy_from_slice(&SIG_UNSTAKE);
    encode_u256(&mut data[4..36], wei);
    send_staking_tx(&data)
}

pub(super) fn claim_rewards() -> Result<[u8; 32], &'static str> {
    use crate::graphics::window::apps::wallet::transaction_parse::derive_signing_key;
    use crate::graphics::window::apps::wallet::transaction_sign::build_and_sign_contract_tx;
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err("Wallet locked");
    }
    let mk = s.master_key.ok_or("No master key")?;
    let (from, idx) = s.get_active_account().map(|a| (a.address, a.index)).ok_or("No account")?;
    drop(s);
    let pending = { STAKING_STATE.lock().pending_rewards };
    if pending == 0 {
        return Err("No rewards");
    }
    let mut data = [0u8; 4];
    data.copy_from_slice(&SIG_CLAIM);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx = build_and_sign_contract_tx(&STAKING_MAINNET, 0, &data, nonce, gp, 150000, 1, &sk)
        .map_err(|_| "Build tx failed")?;
    rpc::send_raw_transaction(&tx).map_err(|_| "Tx broadcast failed")
}

pub(super) fn request_faucet() -> Result<[u8; 32], &'static str> {
    use crate::graphics::window::apps::wallet::transaction_parse::derive_signing_key;
    use crate::graphics::window::apps::wallet::transaction_sign::build_and_sign_contract_tx;
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err("Wallet locked");
    }
    let mk = s.master_key.ok_or("No master key")?;
    let (from, idx) = s.get_active_account().map(|a| (a.address, a.index)).ok_or("No account")?;
    drop(s);
    let mut data = [0u8; 4];
    data.copy_from_slice(&[0x0c, 0x02, 0x05, 0x19]);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx =
        build_and_sign_contract_tx(&FAUCET_SEPOLIA, 0, &data, nonce, gp, 100000, 11155111, &sk)
            .map_err(|_| "Build tx failed")?;
    rpc::send_raw_transaction(&tx).map_err(|_| "Tx broadcast failed")
}

fn send_staking_tx(data: &[u8]) -> Result<[u8; 32], &'static str> {
    use crate::graphics::window::apps::wallet::transaction_parse::derive_signing_key;
    use crate::graphics::window::apps::wallet::transaction_sign::build_and_sign_contract_tx;
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err("Wallet locked");
    }
    let mk = s.master_key.ok_or("No master key")?;
    let (from, idx) = s.get_active_account().map(|a| (a.address, a.index)).ok_or("No account")?;
    drop(s);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx = build_and_sign_contract_tx(&STAKING_MAINNET, 0, data, nonce, gp, 150000, 1, &sk)
        .map_err(|_| "Build tx failed")?;
    rpc::send_raw_transaction(&tx).map_err(|_| "Tx broadcast failed")
}

fn parse_u256_to_u128(data: &[u8]) -> u128 {
    if data.len() < 32 {
        return 0;
    }
    let mut r = 0u128;
    for i in 16..32 {
        r = (r << 8) | data[i] as u128;
    }
    r
}
fn parse_u256_to_u32(data: &[u8]) -> u32 {
    if data.len() < 32 {
        return 0;
    }
    let mut r = 0u32;
    for i in 28..32 {
        r = (r << 8) | data[i] as u32;
    }
    r
}
fn encode_u256(buf: &mut [u8], val: u128) {
    for i in 0..16 {
        buf[i] = 0;
    }
    for i in 0..16 {
        buf[16 + 15 - i] = ((val >> (i * 8)) & 0xff) as u8;
    }
}
