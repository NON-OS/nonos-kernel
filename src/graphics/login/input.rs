// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::auth::{create_new_wallet, get_wallet_count, login_with_wallet};
use super::state::{
    get_screen_state, get_selected_wallet, select_next_wallet, select_prev_wallet,
    set_screen_state, ScreenState,
};

pub fn handle_key(key: u8, _ctrl: bool) -> bool {
    let state = get_screen_state();
    if state == ScreenState::Hidden {
        return false;
    }
    match state {
        ScreenState::Welcome => handle_welcome_key(key),
        ScreenState::WalletSelect => handle_wallet_select_key(key),
        ScreenState::WalletCreate => handle_wallet_create_key(key),
        ScreenState::WalletImport => handle_wallet_import_key(key),
        _ => false,
    }
}

fn handle_welcome_key(key: u8) -> bool {
    match key {
        b'1' | b's' | b'S' => {
            set_screen_state(ScreenState::WalletSelect);
            true
        }
        b'2' | b'c' | b'C' => {
            set_screen_state(ScreenState::WalletCreate);
            true
        }
        b'3' | b'i' | b'I' => {
            set_screen_state(ScreenState::WalletImport);
            true
        }
        0x0D => {
            set_screen_state(ScreenState::WalletSelect);
            true
        }
        _ => false,
    }
}

fn handle_wallet_select_key(key: u8) -> bool {
    let count = get_wallet_count();
    match key {
        0x1B => {
            set_screen_state(ScreenState::Welcome);
            true
        }
        0x26 => {
            select_prev_wallet(count);
            true
        }
        0x28 => {
            select_next_wallet(count);
            true
        }
        0x0D => {
            login_with_wallet(get_selected_wallet());
            true
        }
        c @ b'1'..=b'9' => {
            let idx = c - b'1';
            if idx < count {
                login_with_wallet(idx);
            }
            true
        }
        _ => false,
    }
}

fn handle_wallet_create_key(key: u8) -> bool {
    match key {
        0x1B => {
            set_screen_state(ScreenState::Welcome);
            true
        }
        0x0D => {
            create_new_wallet();
            true
        }
        _ => false,
    }
}

fn handle_wallet_import_key(key: u8) -> bool {
    match key {
        0x1B => {
            set_screen_state(ScreenState::Welcome);
            true
        }
        _ => false,
    }
}

pub fn handle_click(_mx: i32, _my: i32) -> bool {
    let state = get_screen_state();
    state != ScreenState::Hidden
}
