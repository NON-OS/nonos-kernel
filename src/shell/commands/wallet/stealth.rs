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

/* displays stealth address keypair and generates one-time addresses */

use crate::graphics::framebuffer::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE,
    COLOR_YELLOW,
};
use crate::graphics::window::apps::wallet::WALLET_STATE;
use crate::shell::output::print_line;

use super::format::print_stealth;

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
        print_line(b"", COLOR_TEXT);
        print_line(b"Generate with: wallet-stealth-init", COLOR_TEXT_DIM);
    }
}
