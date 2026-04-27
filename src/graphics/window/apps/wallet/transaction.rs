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
use super::network::chain_id;
use super::rpc;
use super::state::*;
use super::transaction_parse::{
    build_erc20_transfer_data, derive_signing_key, parse_eth_address, parse_eth_to_wei,
};
use super::transaction_sign::{build_and_sign_contract_tx, build_and_sign_tx};
use super::types::TokenType;
use core::sync::atomic::Ordering;

pub(super) fn execute_token_send() {
    let tt =
        if SEND_TOKEN_TYPE.load(Ordering::SeqCst) == 0 { TokenType::Eth } else { TokenType::Nox };
    if tt == TokenType::Eth {
        execute_eth_send();
    } else {
        execute_nox_send();
    }
}

fn execute_eth_send() {
    let (ab, al, mb, ml) = {
        (
            SEND_ADDRESS.lock().clone(),
            SEND_ADDRESS_LEN.load(Ordering::SeqCst),
            SEND_AMOUNT.lock().clone(),
            SEND_AMOUNT_LEN.load(Ordering::SeqCst),
        )
    };
    if al < 20 {
        set_status(b"Invalid address", false);
        return;
    }
    if ml == 0 {
        set_status(b"Enter amount", false);
        return;
    }
    let to = match parse_eth_address(core::str::from_utf8(&ab[..al]).unwrap_or("")) {
        Some(a) => a,
        None => {
            set_status(b"Invalid address format", false);
            return;
        }
    };
    let val = match parse_eth_to_wei(core::str::from_utf8(&mb[..ml]).unwrap_or("0")) {
        Some(w) => w,
        None => {
            set_status(b"Invalid amount", false);
            return;
        }
    };
    if !rpc::is_rpc_available() {
        set_status(b"No network", false);
        return;
    }
    set_status(b"Signing...", true);
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        drop(s);
        set_status(b"Wallet locked", false);
        return;
    }
    let mk = match s.master_key {
        Some(k) => k,
        None => {
            drop(s);
            set_status(b"No master key", false);
            return;
        }
    };
    let (from, idx) = match s.get_active_account() {
        Some(a) => (a.address, a.index),
        None => {
            drop(s);
            set_status(b"No account", false);
            return;
        }
    };
    drop(s);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let tx = match build_and_sign_tx(&to, val, nonce, gp, 21000, chain_id(), &sk) {
        Ok(t) => t,
        Err(e) => {
            set_status(e, false);
            return;
        }
    };
    set_status(b"Broadcasting...", true);
    match rpc::send_raw_transaction(&tx) {
        Ok(h) => {
            let mut st = WALLET_STATE.lock();
            st.pending_transactions.push(super::types::Transaction {
                hash: h,
                tx_type: super::types::TransactionType::Send,
                from,
                to,
                value: val,
                timestamp: crate::time::timestamp_millis() / 1000,
                confirmed: false,
            });
            drop(st);
            set_status(b"ETH sent!", true);
            clear_send_fields();
        }
        Err(_) => {
            set_status(b"Broadcast failed", false);
        }
    }
}

fn execute_nox_send() {
    let (ab, al, mb, ml) = {
        (
            SEND_ADDRESS.lock().clone(),
            SEND_ADDRESS_LEN.load(Ordering::SeqCst),
            SEND_AMOUNT.lock().clone(),
            SEND_AMOUNT_LEN.load(Ordering::SeqCst),
        )
    };
    if al < 20 {
        set_status(b"Invalid address", false);
        return;
    }
    if ml == 0 {
        set_status(b"Enter amount", false);
        return;
    }
    let to = match parse_eth_address(core::str::from_utf8(&ab[..al]).unwrap_or("")) {
        Some(a) => a,
        None => {
            set_status(b"Invalid address format", false);
            return;
        }
    };
    let val = match parse_eth_to_wei(core::str::from_utf8(&mb[..ml]).unwrap_or("0")) {
        Some(w) => w,
        None => {
            set_status(b"Invalid amount", false);
            return;
        }
    };
    if !rpc::is_rpc_available() {
        set_status(b"No network", false);
        return;
    }
    set_status(b"Signing token tx...", true);
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        drop(s);
        set_status(b"Wallet locked", false);
        return;
    }
    let mk = match s.master_key {
        Some(k) => k,
        None => {
            drop(s);
            set_status(b"No master key", false);
            return;
        }
    };
    let (from, idx) = match s.get_active_account() {
        Some(a) => (a.address, a.index),
        None => {
            drop(s);
            set_status(b"No account", false);
            return;
        }
    };
    drop(s);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let data = build_erc20_transfer_data(&to, val);
    let contract = super::network::nox_contract();
    let tx =
        match build_and_sign_contract_tx(&contract, 0, &data, nonce, gp, 100000, chain_id(), &sk) {
            Ok(t) => t,
            Err(e) => {
                set_status(e, false);
                return;
            }
        };
    set_status(b"Broadcasting...", true);
    match rpc::send_raw_transaction(&tx) {
        Ok(h) => {
            let mut st = WALLET_STATE.lock();
            st.pending_transactions.push(super::types::Transaction {
                hash: h,
                tx_type: super::types::TransactionType::ContractCall,
                from,
                to,
                value: val,
                timestamp: crate::time::timestamp_millis() / 1000,
                confirmed: false,
            });
            drop(st);
            set_status(b"NOX sent!", true);
            clear_send_fields();
        }
        Err(_) => {
            set_status(b"Broadcast failed", false);
        }
    }
}
