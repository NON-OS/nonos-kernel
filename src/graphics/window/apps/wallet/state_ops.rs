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

    let stealth_seed = blake3_hash(&[&master_key[..], b"NONOS:WALLET:STEALTH"].concat());
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

    let mut path = alloc::vec::Vec::with_capacity(32 + 21 + 4);
    path.extend_from_slice(master_key);
    path.extend_from_slice(b"NONOS:WALLET:ACCOUNT:");
    path.extend_from_slice(&index.to_le_bytes());

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

    let account = WalletAccount::new(index, address);
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

    let mut state = WALLET_STATE.lock();
    if !state.unlocked {
        return;
    }

    let mut success_count = 0;
    let total_accounts = state.accounts.len();

    for account in state.accounts.iter_mut() {
        match rpc::fetch_balance(&account.address) {
            Ok(balance) => {
                account.balance = balance;
                success_count += 1;
            }
            Err(_) => {}
        }
    }

    drop(state);

    if success_count == total_accounts {
        set_status(b"Balances updated", true);
    } else if success_count > 0 {
        set_status(b"Partial update", false);
    } else {
        set_status(b"Update failed", false);
    }
}

pub(crate) fn get_block_number() -> Option<u64> {
    use super::rpc;

    if !rpc::is_rpc_available() {
        return None;
    }

    rpc::fetch_block_number().ok()
}

pub(crate) fn set_active_account(index: usize) {
    let mut state = WALLET_STATE.lock();
    state.set_active_account(index);
    drop(state);
    set_status(b"Account selected", true);
}
