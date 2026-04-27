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

/* signs arbitrary messages with secp256k1 using eth personal_sign format */

use crate::crypto::asymmetric::secp256k1::sign_recoverable;
use crate::crypto::hash::keccak256;
use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use crate::graphics::window::apps::wallet::WALLET_STATE;
use crate::shell::output::print_line;

use super::util::trim_bytes;

pub fn cmd_wallet_sign(cmd: &[u8]) {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    let account = match state.get_active_account() {
        Some(acc) => acc,
        None => {
            drop(state);
            print_line(b"No active account", COLOR_RED);
            return;
        }
    };

    let secret_key = account.secret_key;
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

    let prefixed = build_eth_signed_message(msg);
    let msg_hash = keccak256(&prefixed);

    let sig = match sign_recoverable(&secret_key, &msg_hash) {
        Some(s) => s,
        None => {
            print_line(b"Signing failed", COLOR_RED);
            return;
        }
    };

    print_line(b"Signature", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    print_line(b"Hash:", COLOR_TEXT_DIM);
    print_hex_line(&msg_hash);

    print_line(b"Sig:", COLOR_TEXT_DIM);
    print_signature(&sig.r, &sig.s, sig.recovery_id);

    print_line(b"", COLOR_TEXT_DIM);
    print_line(b"Format: EIP-191 personal_sign", COLOR_GREEN);
}

fn build_eth_signed_message(msg: &[u8]) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    use alloc::vec::Vec;

    let prefix = b"\x19Ethereum Signed Message:\n";
    let len_str = format_len(msg.len());

    let mut result = Vec::with_capacity(prefix.len() + len_str.len() + msg.len());
    result.extend_from_slice(prefix);
    result.extend_from_slice(&len_str);
    result.extend_from_slice(msg);
    result
}

fn format_len(len: usize) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    use alloc::vec::Vec;

    if len == 0 {
        return alloc::vec![b'0'];
    }

    let mut digits = Vec::new();
    let mut n = len;
    while n > 0 {
        digits.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    digits
}

fn print_hex_line(bytes: &[u8; 32]) {
    extern crate alloc;
    use alloc::string::String;

    let mut hex = String::with_capacity(66);
    hex.push_str("0x");
    for byte in bytes {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    print_line(hex.as_bytes(), COLOR_TEXT_DIM);
}

fn print_signature(r: &[u8; 32], s: &[u8; 32], v: u8) {
    extern crate alloc;
    use alloc::string::String;

    let mut hex = String::with_capacity(132);
    hex.push_str("0x");
    for byte in r {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    for byte in s {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    hex.push_str(&alloc::format!("{:02x}", v + 27));

    print_line(hex.as_bytes(), COLOR_TEXT_DIM);
}
