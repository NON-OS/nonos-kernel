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
    COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::graphics::window::apps::wallet::{WALLET_STATE, format_address};
use crate::shell::output::print_line;

use super::format::{print_addr, print_count};

pub fn cmd_wallet_status() {
    print_line(b"NONOS Wallet", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = WALLET_STATE.lock();
    if state.unlocked {
        print_line(b"Status: UNLOCKED", COLOR_GREEN);
        print_line(b"", COLOR_TEXT);

        if let Some(account) = state.get_active_account() {
            print_line(b"Active Account:", COLOR_ACCENT);
            let addr = format_address(&account.address);
            print_addr(b"  Address: ", &addr);
            print_line(b"  Token:   NOX", COLOR_TEXT);
        }

        print_line(b"", COLOR_TEXT);
        print_count(b"Accounts: ", state.accounts.len());

        if state.stealth_keypair.is_some() {
            print_line(b"Stealth: ENABLED", COLOR_GREEN);
        }
    } else {
        print_line(b"Status: LOCKED", COLOR_YELLOW);
        print_line(b"", COLOR_TEXT);
        print_line(b"wallet-new        Generate new key", COLOR_TEXT_DIM);
        print_line(b"wallet-unlock     Unlock with key", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Security:", COLOR_ACCENT);
    print_line(b"  Keys: RAM only (ZeroState)", COLOR_GREEN);
    print_line(b"  Stealth: Enabled", COLOR_GREEN);
    print_line(b"  Network: Anyone", COLOR_GREEN);
}

pub fn cmd_wallet_help() {
    print_line(b"NONOS Wallet", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"wallet            Status", COLOR_ACCENT);
    print_line(b"wallet-new        Generate key", COLOR_ACCENT);
    print_line(b"wallet-unlock     Unlock with key", COLOR_ACCENT);
    print_line(b"wallet-lock       Lock wallet", COLOR_ACCENT);
    print_line(b"wallet-address    Show addresses", COLOR_ACCENT);
    print_line(b"wallet-balance    Show balance", COLOR_ACCENT);
    print_line(b"wallet-send       Send NOX", COLOR_ACCENT);
    print_line(b"wallet-derive     Derive account", COLOR_ACCENT);
    print_line(b"wallet-stealth    Stealth info", COLOR_ACCENT);
    print_line(b"wallet-sign       Sign message", COLOR_ACCENT);
    print_line(b"wallet-export     Export key", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Token: NOX", COLOR_GREEN);
    print_line(b"Keys: RAM only", COLOR_GREEN);
}
