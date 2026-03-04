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

use super::state::*;
use super::rlp::*;

pub(super) fn execute_send() {
    use super::rpc;
    use super::types::ADDRESS_LEN;

    let addr_buf = SEND_ADDRESS.lock();
    let addr_len = SEND_ADDRESS_LEN.load(Ordering::SeqCst);
    let amount_buf = SEND_AMOUNT.lock();
    let amount_len = SEND_AMOUNT_LEN.load(Ordering::SeqCst);

    if addr_len < ADDRESS_LEN {
        set_status(b"Invalid address", false);
        return;
    }

    if amount_len == 0 {
        set_status(b"Enter amount", false);
        return;
    }

    let addr_str = core::str::from_utf8(&addr_buf[..addr_len]).unwrap_or("");
    let to_address = match parse_eth_address(addr_str) {
        Some(addr) => addr,
        None => {
            drop(addr_buf);
            drop(amount_buf);
            set_status(b"Invalid address format", false);
            return;
        }
    };

    let amount_str = core::str::from_utf8(&amount_buf[..amount_len]).unwrap_or("0");
    let value_wei = match parse_eth_to_wei(amount_str) {
        Some(wei) => wei,
        None => {
            drop(addr_buf);
            drop(amount_buf);
            set_status(b"Invalid amount", false);
            return;
        }
    };

    drop(addr_buf);
    drop(amount_buf);

    if !rpc::is_rpc_available() {
        set_status(b"No network connection", false);
        return;
    }

    set_status(b"Signing transaction...", true);

    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        set_status(b"Wallet locked", false);
        return;
    }

    let master_key = match state.master_key {
        Some(k) => k,
        None => {
            drop(state);
            set_status(b"No master key", false);
            return;
        }
    };

    let sender_address = match state.get_active_account() {
        Some(acc) => acc.address,
        None => {
            drop(state);
            set_status(b"No active account", false);
            return;
        }
    };
    drop(state);

    let nonce = match rpc::fetch_nonce(&sender_address) {
        Ok(n) => n,
        Err(_) => {
            set_status(b"Failed to get nonce", false);
            return;
        }
    };

    let gas_price = match rpc::fetch_gas_price() {
        Ok(p) => p,
        Err(_) => {
            set_status(b"Failed to get gas price", false);
            return;
        }
    };

    let secret_key = derive_signing_key(&master_key, 0);

    let signed_tx = match build_and_sign_tx(
        &to_address,
        value_wei,
        nonce,
        gas_price,
        21000,
        1,
        &secret_key,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            set_status(e, false);
            return;
        }
    };

    set_status(b"Broadcasting...", true);

    match rpc::send_raw_transaction(&signed_tx) {
        Ok(tx_hash) => {
            let mut state = WALLET_STATE.lock();
            state.pending_transactions.push(super::types::Transaction {
                hash: tx_hash,
                tx_type: super::types::TransactionType::Send,
                from: sender_address,
                to: to_address,
                value: value_wei,
                timestamp: crate::time::timestamp_millis() / 1000,
                confirmed: false,
            });
            drop(state);

            set_status(b"Transaction sent!", true);
            clear_send_fields();
        }
        Err(_) => {
            set_status(b"Broadcast failed", false);
        }
    }
}

fn parse_eth_address(addr: &str) -> Option<[u8; 20]> {
    let hex = addr.strip_prefix("0x").unwrap_or(addr);
    if hex.len() != 40 {
        return None;
    }

    let mut address = [0u8; 20];
    for i in 0..20 {
        let byte_hex = &hex[i * 2..i * 2 + 2];
        address[i] = u8::from_str_radix(byte_hex, 16).ok()?;
    }
    Some(address)
}

fn parse_eth_to_wei(amount: &str) -> Option<u128> {
    let parts: alloc::vec::Vec<&str> = amount.split('.').collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }

    let whole: u128 = parts[0].parse().ok()?;
    let fraction: u128 = if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.len() > 18 {
            return None;
        }
        let mut frac: u128 = frac_str.parse().ok()?;
        for _ in 0..(18 - frac_str.len()) {
            frac = frac.checked_mul(10)?;
        }
        frac
    } else {
        0
    };

    let whole_wei = whole.checked_mul(1_000_000_000_000_000_000)?;
    whole_wei.checked_add(fraction)
}

fn derive_signing_key(master_key: &[u8; 32], index: u32) -> [u8; 32] {
    use crate::crypto::blake3_hash;

    let mut path = alloc::vec::Vec::with_capacity(32 + 21 + 4);
    path.extend_from_slice(master_key);
    path.extend_from_slice(b"NONOS:WALLET:ACCOUNT:");
    path.extend_from_slice(&index.to_le_bytes());

    let seed = blake3_hash(&path);
    let mut key = [0u8; 32];
    key.copy_from_slice(&seed);
    key
}

fn build_and_sign_tx(
    to: &[u8; 20],
    value: u128,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    chain_id: u64,
    secret_key: &[u8; 32],
) -> Result<alloc::vec::Vec<u8>, &'static [u8]> {
    use crate::crypto::secp256k1::sign_recoverable;
    use crate::crypto::keccak256;

    let mut items = alloc::vec::Vec::new();

    items.push(rlp_encode_u64(nonce));
    items.push(rlp_encode_u128(gas_price));
    items.push(rlp_encode_u64(gas_limit));
    items.push(rlp_encode_bytes(to));
    items.push(rlp_encode_u128(value));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_u64(chain_id));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_bytes(&[]));

    let unsigned = rlp_encode_list(&items);
    let hash = keccak256(&unsigned);

    let sig = sign_recoverable(secret_key, &hash).ok_or(b"Sign failed" as &[u8])?;
    let v = (sig.recovery_id as u64) + 35 + chain_id * 2;

    let mut signed_items = alloc::vec::Vec::new();
    signed_items.push(rlp_encode_u64(nonce));
    signed_items.push(rlp_encode_u128(gas_price));
    signed_items.push(rlp_encode_u64(gas_limit));
    signed_items.push(rlp_encode_bytes(to));
    signed_items.push(rlp_encode_u128(value));
    signed_items.push(rlp_encode_bytes(&[]));
    signed_items.push(rlp_encode_u64(v));
    signed_items.push(rlp_encode_bytes(&sig.r));
    signed_items.push(rlp_encode_bytes(&sig.s));

    Ok(rlp_encode_list(&signed_items))
}
