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

use core::sync::atomic::Ordering;

use super::types::{WalletAccount, ADDRESS_LEN};
use super::network::nox_contract;
use super::stealth::StealthKeyPair;
use super::state::{
    WALLET_STATE, SEND_ADDRESS, SEND_ADDRESS_LEN, SEND_AMOUNT, SEND_AMOUNT_LEN,
    SEND_FIELD, INPUT_CURSOR, set_status,
};

pub(crate) fn init_wallet(master_key: [u8; 32]) -> Result<(), &'static str> {
    use crate::crypto::secp256k1::{self, Scalar};
    use crate::crypto::blake3_hash;

    let mut state = WALLET_STATE.lock();
    if state.unlocked {
        return Err("wallet already unlocked");
    }

    let account_seed = derive_account_seed(&master_key, 0);
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&account_seed);

    if Scalar::from_bytes(&secret_key).is_none() {
        return Err("invalid derived key");
    }

    let public_key = match secp256k1::public_key_from_secret(&secret_key) {
        Some(pk) => pk,
        None => return Err("failed to derive public key"),
    };
    let address = secp256k1::eth_address(&public_key);

    let account = WalletAccount::with_secret_key(0, address, secret_key);
    state.accounts.push(account);

    /* Use fixed-size array for stealth key derivation */
    let mut stealth_path = [0u8; 52]; /* 32 + 20 */
    stealth_path[0..32].copy_from_slice(&master_key);
    stealth_path[32..52].copy_from_slice(b"NONOS:WALLET:STEALTH");
    let stealth_seed = blake3_hash(&stealth_path);
    state.stealth_keypair = Some(StealthKeyPair::from_seed(&stealth_seed));

    state.master_key = Some(master_key);
    state.unlocked = true;

    set_status(b"Wallet unlocked", true);
    Ok(())
}

pub(crate) fn lock_wallet() {
    let mut state = WALLET_STATE.lock();
    state.lock();
    set_status(b"Wallet locked", true);
}

fn derive_account_seed(master_key: &[u8; 32], index: u32) -> [u8; 32] {
    use crate::crypto::blake3_hash;

    /* Use fixed-size array to avoid potential Vec issues in no_std environment.
     * Path format: master_key (32) + "NONOS:WALLET:ACCOUNT:" (21) + index_le (4) = 57 bytes */
    let mut path = [0u8; 57];
    path[0..32].copy_from_slice(master_key);
    path[32..53].copy_from_slice(b"NONOS:WALLET:ACCOUNT:");
    path[53..57].copy_from_slice(&index.to_le_bytes());

    blake3_hash(&path)
}

pub(crate) fn derive_account(index: u32) -> Result<[u8; ADDRESS_LEN], &'static str> {
    use crate::crypto::secp256k1::{self, Scalar};

    let mut state = WALLET_STATE.lock();
    if !state.unlocked {
        return Err("wallet locked");
    }

    let master_key = state.master_key.ok_or("no master key")?;

    let account_seed = derive_account_seed(&master_key, index);
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&account_seed);

    if Scalar::from_bytes(&secret_key).is_none() {
        return Err("invalid derived key");
    }

    let public_key = match secp256k1::public_key_from_secret(&secret_key) {
        Some(pk) => pk,
        None => return Err("failed to derive public key"),
    };
    let address = secp256k1::eth_address(&public_key);

    for acc in &state.accounts {
        if acc.address == address {
            return Err("account already exists");
        }
    }

    let account = WalletAccount::with_secret_key(index, address, secret_key);
    state.accounts.push(account);

    Ok(address)
}

pub(crate) fn clear_send_fields() {
    let mut addr = SEND_ADDRESS.lock();
    for byte in addr.iter_mut() {
        *byte = 0;
    }
    SEND_ADDRESS_LEN.store(0, Ordering::SeqCst);

    let mut amount = SEND_AMOUNT.lock();
    for byte in amount.iter_mut() {
        *byte = 0;
    }
    SEND_AMOUNT_LEN.store(0, Ordering::SeqCst);

    SEND_FIELD.store(0, Ordering::SeqCst);
    INPUT_CURSOR.store(0, Ordering::SeqCst);
}

pub(crate) fn refresh_balances() {
    use super::rpc;

    if !rpc::is_rpc_available() {
        set_status(b"No network connection", false);
        return;
    }

    set_status(b"Fetching...", true);

    let (addr, active_idx) = {
        let state = WALLET_STATE.lock();
        if !state.unlocked {
            return;
        }
        match state.get_active_account() {
            Some(acc) => (acc.address, state.active_account),
            None => return,
        }
    };

    let nox_addr = nox_contract();
    let eth = rpc::fetch_balance(&addr).unwrap_or(0);
    let nox = rpc::fetch_token_balance(&nox_addr, &addr).unwrap_or(0);

    {
        let mut state = WALLET_STATE.lock();
        if active_idx < state.accounts.len() {
            state.accounts[active_idx].balance = eth;
            state.accounts[active_idx].nox_balance = nox;
        }
    }

    if let Ok(block) = rpc::fetch_block_number() {
        super::state::CACHED_BLOCK.store(block, Ordering::Relaxed);
    }

    if eth > 0 || nox > 0 {
        set_status(b"Balance updated", true);
    } else {
        set_status(b"Balance: 0", true);
    }
}

pub(crate) fn set_active_account(index: usize) {
    let mut state = WALLET_STATE.lock();
    state.set_active_account(index);
    drop(state);
    set_status(b"Account selected", true);
}
