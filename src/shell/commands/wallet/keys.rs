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
    COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::graphics::window::apps::wallet::{WALLET_STATE, init_wallet, lock_wallet, format_address};
use crate::shell::output::print_line;

use super::util::{trim_bytes, print_hex32_out};
use super::format::{print_addr, print_err, hex_val};

pub fn cmd_wallet_new() {
    print_line(b"Generate New Wallet", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = WALLET_STATE.lock();
    if state.unlocked {
        drop(state);
        print_line(b"Wallet active. Lock first.", COLOR_YELLOW);
        return;
    }
    drop(state);

    let master_key = crate::crypto::get_random_bytes();

    print_line(b"", COLOR_TEXT);
    print_line(b"PRIVATE KEY - BACKUP THIS!", COLOR_RED);
    print_line(b"", COLOR_TEXT);
    print_hex32_out(&master_key);
    print_line(b"", COLOR_TEXT);

    match init_wallet(master_key) {
        Ok(()) => {
            print_line(b"Wallet created", COLOR_GREEN);
            let state = WALLET_STATE.lock();
            if let Some(account) = state.get_active_account() {
                let addr = format_address(&account.address);
                print_line(b"", COLOR_TEXT);
                print_line(b"Your NOX address:", crate::graphics::framebuffer::COLOR_ACCENT);
                print_addr(b"  ", &addr);
            }
        }
        Err(e) => {
            print_err(e);
        }
    }
}

pub fn cmd_wallet_unlock(cmd: &[u8]) {
    let key_hex = if cmd.len() > 14 {
        trim_bytes(&cmd[14..])
    } else {
        print_line(b"Usage: wallet-unlock <64-char-hex-key>", COLOR_TEXT_DIM);
        return;
    };

    if key_hex.len() != 64 {
        print_line(b"Key must be 64 hex chars (32 bytes)", COLOR_RED);
        return;
    }

    let mut master_key = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(key_hex[i * 2]);
        let lo = hex_val(key_hex[i * 2 + 1]);
        if hi == 0xFF || lo == 0xFF {
            print_line(b"Invalid hex", COLOR_RED);
            return;
        }
        master_key[i] = (hi << 4) | lo;
    }

    match init_wallet(master_key) {
        Ok(()) => {
            print_line(b"Wallet unlocked", COLOR_GREEN);
            let state = WALLET_STATE.lock();
            if let Some(account) = state.get_active_account() {
                let addr = format_address(&account.address);
                print_addr(b"Address: ", &addr);
            }
        }
        Err(e) => {
            print_err(e);
        }
    }
}

pub fn cmd_wallet_lock() {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet not unlocked", COLOR_YELLOW);
        return;
    }
    drop(state);

    lock_wallet();
    print_line(b"Wallet locked", COLOR_GREEN);
    print_line(b"Keys erased", COLOR_TEXT_DIM);
}

pub fn cmd_wallet_export() {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    let master_key = match state.master_key {
        Some(key) => key,
        None => {
            drop(state);
            print_line(b"No key", COLOR_RED);
            return;
        }
    };
    drop(state);

    print_line(b"PRIVATE KEY EXPORT", COLOR_RED);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_hex32_out(&master_key);
    print_line(b"", COLOR_TEXT);
    print_line(b"DO NOT SHARE!", COLOR_RED);
}
