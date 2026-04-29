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

use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScreenState {
    Hidden = 0,
    Welcome = 1,
    WalletSelect = 2,
    WalletCreate = 3,
    WalletImport = 4,
}

static SCREEN_STATE: AtomicU8 = AtomicU8::new(1);
static SELECTED_WALLET: AtomicU8 = AtomicU8::new(0);

pub fn get_screen_state() -> ScreenState {
    match SCREEN_STATE.load(Ordering::Relaxed) {
        1 => ScreenState::Welcome,
        2 => ScreenState::WalletSelect,
        3 => ScreenState::WalletCreate,
        4 => ScreenState::WalletImport,
        _ => ScreenState::Hidden,
    }
}

pub(super) fn set_screen_state(state: ScreenState) {
    SCREEN_STATE.store(state as u8, Ordering::Relaxed);
}

pub fn is_login_required() -> bool {
    get_screen_state() != ScreenState::Hidden
}

pub fn is_locked() -> bool {
    false
}

pub fn lock_screen() {}

pub(super) fn get_selected_wallet() -> u8 {
    SELECTED_WALLET.load(Ordering::Relaxed)
}

pub(super) fn select_next_wallet(count: u8) {
    let cur = SELECTED_WALLET.load(Ordering::Relaxed);
    SELECTED_WALLET.store((cur + 1) % count.max(1), Ordering::Relaxed);
}

pub(super) fn select_prev_wallet(count: u8) {
    let cur = SELECTED_WALLET.load(Ordering::Relaxed);
    SELECTED_WALLET.store(if cur == 0 { count.saturating_sub(1) } else { cur - 1 }, Ordering::Relaxed);
}

pub(super) fn complete_login() {
    set_screen_state(ScreenState::Hidden);
}
