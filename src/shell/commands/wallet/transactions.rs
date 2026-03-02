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

use crate::crypto::blake3_hash;
use crate::graphics::framebuffer::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::graphics::window::apps::wallet::WALLET_STATE;
use crate::shell::output::print_line;

use super::util::{trim_bytes, print_hex32_out};
use super::format::print_stealth;

pub fn cmd_wallet_send(cmd: &[u8]) {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }
    drop(state);

    let args = if cmd.len() > 12 {
        trim_bytes(&cmd[12..])
    } else {
        print_line(b"Usage: wallet-send <addr> <amount>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"Missing address and amount", COLOR_RED);
        return;
    }

    print_line(b"Transaction", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Token: NOX", COLOR_ACCENT);
    print_line(b"Route: Anyone", COLOR_GREEN);
    print_line(b"Privacy: Stealth", COLOR_GREEN);
}

pub fn cmd_wallet_sign(cmd: &[u8]) {
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

    let msg = if cmd.len() > 12 {
        trim_bytes(&cmd[12..])
    } else {
        print_line(b"Usage: wallet-sign <message>", COLOR_TEXT_DIM);
        return;
    };

    if msg.is_empty() {
        print_line(b"Message required", COLOR_RED);
        return;
    }

    let msg_hash = blake3_hash(msg);
    let mut sig_input = [0u8; 64];
    sig_input[..32].copy_from_slice(&master_key);
    sig_input[32..].copy_from_slice(&msg_hash);
    let sig = blake3_hash(&sig_input);

    print_line(b"Signature", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Hash:", COLOR_TEXT_DIM);
    print_hex32_out(&msg_hash);
    print_line(b"Sig:", COLOR_TEXT_DIM);
    print_hex32_out(&sig);
}

pub fn cmd_wallet_stealth() {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    print_line(b"Stealth Addresses", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    if let Some(ref kp) = state.stealth_keypair {
        print_line(b"Status: ACTIVE", COLOR_GREEN);
        print_line(b"", COLOR_TEXT);
        print_line(b"Meta-Address:", COLOR_ACCENT);
        let meta = kp.meta_address();
        let enc = meta.encode();
        print_stealth(&enc);
        print_line(b"", COLOR_TEXT);
        print_line(b"One-time addresses per payment", COLOR_TEXT_DIM);
        print_line(b"Unlinkable transactions", COLOR_TEXT_DIM);
    } else {
        print_line(b"Status: NOT ACTIVE", COLOR_YELLOW);
    }
}
