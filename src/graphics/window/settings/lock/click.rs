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

use super::state;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;

pub fn handle_click(_rel_x: u32, rel_y: u32, _content_w: u32) -> bool {
    if rel_y < SECTION_Y {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => toggle_require_wallet(),
        1 => toggle_lock_after_sleep(),
        2 => cycle_lock_timeout(),
        3 => toggle_show_message(),
        4 => toggle_auto_login(),
        5 => cycle_screensaver(),
        6 => cycle_screensaver_timeout(),
        _ => false,
    }
}

fn toggle_require_wallet() -> bool {
    let v = state::get_state().require_wallet;
    state::set_require_wallet(!v);
    true
}

fn toggle_lock_after_sleep() -> bool {
    let v = state::get_state().lock_after_sleep;
    state::set_lock_after_sleep(!v);
    true
}

fn cycle_lock_timeout() -> bool {
    let current = state::get_state().lock_timeout_idx;
    let count = state::LOCK_TIMEOUTS.len() as u8;
    state::set_lock_timeout((current + 1) % count);
    true
}

fn toggle_show_message() -> bool {
    let v = state::get_state().show_message;
    state::set_show_message(!v);
    true
}

fn toggle_auto_login() -> bool {
    let v = state::get_state().auto_login;
    state::set_auto_login(!v);
    true
}

fn cycle_screensaver() -> bool {
    let current = state::get_state().screensaver_idx;
    let count = state::SCREENSAVERS.len() as u8;
    state::set_screensaver((current + 1) % count);
    true
}

fn cycle_screensaver_timeout() -> bool {
    let current = state::get_state().screensaver_timeout_idx;
    let count = state::LOCK_TIMEOUTS.len() as u8;
    state::set_screensaver_timeout((current + 1) % count);
    true
}
