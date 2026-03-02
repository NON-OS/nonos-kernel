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

use crate::graphics::framebuffer::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE,
};
use crate::graphics::window::apps::wallet::{WALLET_STATE, derive_account, format_address};
use crate::shell::output::print_line;

use super::format::{print_addr, print_account, print_stealth, print_balance, print_err};

pub fn cmd_wallet_address() {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    print_line(b"Addresses", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    for (i, account) in state.accounts.iter().enumerate() {
        let addr = format_address(&account.address);
        let active = i == state.active_account;
        print_account(i, &addr, active);
    }

    if let Some(ref kp) = state.stealth_keypair {
        print_line(b"", COLOR_TEXT);
        print_line(b"Stealth Meta-Address:", COLOR_ACCENT);
        let meta = kp.meta_address();
        let enc = meta.encode();
        print_stealth(&enc);
    }
}

pub fn cmd_wallet_balance() {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    print_line(b"Balance", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Token: NOX", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);

    if let Some(account) = state.get_active_account() {
        let (eth, wei) = account.balance_eth();
        print_balance(eth, wei);
    }
}

pub fn cmd_wallet_derive(_cmd: &[u8]) {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }
    let idx = state.accounts.len() as u32;
    drop(state);

    match derive_account(idx) {
        Ok(address) => {
            let addr = format_address(&address);
            print_line(b"Account derived:", COLOR_GREEN);
            print_addr(b"  ", &addr);
        }
        Err(e) => {
            print_err(e);
        }
    }
}
