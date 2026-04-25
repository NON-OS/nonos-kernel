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
use super::network::nox_contract;
use super::state::{
    set_status, CACHED_BLOCK, INPUT_CURSOR, REFRESH_IN_PROGRESS, SEND_ADDRESS, SEND_ADDRESS_LEN,
    SEND_AMOUNT, SEND_AMOUNT_LEN, SEND_FIELD, WALLET_STATE,
};
use super::stealth::StealthKeyPair;
use super::types::{WalletAccount, ADDRESS_LEN};
use crate::crypto::{
    blake3_hash,
    secp256k1::{self, Scalar},
};
use core::sync::atomic::Ordering;

fn derive_seed(mk: &[u8; 32], i: u32) -> [u8; 32] {
    let mut p = [0u8; 57];
    p[0..32].copy_from_slice(mk);
    p[32..53].copy_from_slice(b"NONOS:WALLET:ACCOUNT:");
    p[53..57].copy_from_slice(&i.to_le_bytes());
    blake3_hash(&p)
}

pub(crate) fn init_wallet(mk: [u8; 32]) -> Result<(), &'static str> {
    let mut s = WALLET_STATE.lock();
    if s.unlocked {
        return Err("wallet already unlocked");
    }
    let seed = derive_seed(&mk, 0);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed);
    if Scalar::from_bytes(&sk).is_none() {
        return Err("invalid derived key");
    }
    let pk = secp256k1::public_key_from_secret(&sk).ok_or("failed to derive public key")?;
    s.accounts.push(WalletAccount::with_secret_key(0, secp256k1::eth_address(&pk), sk));
    let mut sp = [0u8; 52];
    sp[0..32].copy_from_slice(&mk);
    sp[32..52].copy_from_slice(b"NONOS:WALLET:STEALTH");
    s.stealth_keypair = Some(StealthKeyPair::from_seed(&blake3_hash(&sp)));
    s.master_key = Some(mk);
    s.unlocked = true;
    set_status(b"Wallet unlocked", true);
    Ok(())
}

pub(crate) fn lock_wallet() {
    WALLET_STATE.lock().lock();
    set_status(b"Wallet locked", true);
}

pub(crate) fn derive_account(i: u32) -> Result<[u8; ADDRESS_LEN], &'static str> {
    let mut s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err("wallet locked");
    }
    let mk = s.master_key.ok_or("no master key")?;
    let seed = derive_seed(&mk, i);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed);
    if Scalar::from_bytes(&sk).is_none() {
        return Err("invalid derived key");
    }
    let pk = secp256k1::public_key_from_secret(&sk).ok_or("failed to derive public key")?;
    let addr = secp256k1::eth_address(&pk);
    for a in &s.accounts {
        if a.address == addr {
            return Err("account already exists");
        }
    }
    s.accounts.push(WalletAccount::with_secret_key(i, addr, sk));
    Ok(addr)
}

pub(crate) fn clear_send_fields() {
    for b in SEND_ADDRESS.lock().iter_mut() {
        *b = 0;
    }
    SEND_ADDRESS_LEN.store(0, Ordering::SeqCst);
    for b in SEND_AMOUNT.lock().iter_mut() {
        *b = 0;
    }
    SEND_AMOUNT_LEN.store(0, Ordering::SeqCst);
    SEND_FIELD.store(0, Ordering::SeqCst);
    INPUT_CURSOR.store(0, Ordering::SeqCst);
}

pub(crate) fn refresh_balances() {
    use super::rpc;
    if REFRESH_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        return;
    }
    if !rpc::is_rpc_available() {
        REFRESH_IN_PROGRESS.store(false, Ordering::SeqCst);
        set_status(b"No network connection", false);
        return;
    }
    set_status(b"Fetching...", true);
    let (addr, idx) = {
        let s = WALLET_STATE.lock();
        if !s.unlocked {
            REFRESH_IN_PROGRESS.store(false, Ordering::SeqCst);
            return;
        }
        match s.get_active_account() {
            Some(a) => (a.address, s.active_account),
            None => {
                REFRESH_IN_PROGRESS.store(false, Ordering::SeqCst);
                return;
            }
        }
    };
    let eth = rpc::fetch_balance(&addr).unwrap_or(0);
    let nox = rpc::fetch_token_balance(&nox_contract(), &addr).unwrap_or(0);
    if let Ok(b) = rpc::fetch_block_number() {
        CACHED_BLOCK.store(b, Ordering::SeqCst);
    }
    {
        let mut s = WALLET_STATE.lock();
        if idx < s.accounts.len() {
            s.accounts[idx].balance = eth;
            s.accounts[idx].nox_balance = nox;
        }
    }
    REFRESH_IN_PROGRESS.store(false, Ordering::SeqCst);
    set_status(if eth > 0 || nox > 0 { b"Balance updated" } else { b"Balance: 0" }, true);
}

pub(crate) fn set_active_account(i: usize) {
    WALLET_STATE.lock().set_active_account(i);
    set_status(b"Account selected", true);
}
