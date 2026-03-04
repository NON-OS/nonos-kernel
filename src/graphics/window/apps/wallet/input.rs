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

use crate::graphics::window::text_editor::SpecialKey;

use super::state::*;

const SIDEBAR_WIDTH: u32 = 180;
const HEADER_HEIGHT: u32 = 60;

pub(super) fn handle_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    let rel_x = (click_x - win_x as i32) as u32;
    let rel_y = (click_y - win_y as i32) as u32;

    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        return super::click_locked::handle_locked_click(rel_x, rel_y, win_w, win_h);
    }
    drop(state);

    if rel_x < SIDEBAR_WIDTH {
        return super::click_overview::handle_sidebar_click(rel_y);
    }

    let view = get_view();
    let content_h = win_h - HEADER_HEIGHT - 30;
    match view {
        WalletView::Overview => super::click_overview::handle_overview_click(rel_x - SIDEBAR_WIDTH, rel_y - HEADER_HEIGHT, win_w - SIDEBAR_WIDTH),
        WalletView::Send => super::click_send::handle_send_click(rel_x - SIDEBAR_WIDTH, rel_y - HEADER_HEIGHT, win_w - SIDEBAR_WIDTH),
        WalletView::Stealth => super::click_send::handle_stealth_click(rel_x - SIDEBAR_WIDTH, rel_y - HEADER_HEIGHT, win_w - SIDEBAR_WIDTH, content_h),
        WalletView::Settings => super::click_send::handle_settings_click(rel_x - SIDEBAR_WIDTH, rel_y - HEADER_HEIGHT, win_w - SIDEBAR_WIDTH),
        _ => false,
    }
}

pub(super) fn handle_key(ch: u8) {
    super::keyboard::handle_key(ch);
}

pub(super) fn handle_special_key(key: SpecialKey) {
    super::keyboard::handle_special_key(key);
}
