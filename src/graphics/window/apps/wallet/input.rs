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

use super::state::*;
use crate::graphics::window::text_editor::SpecialKey;

const SIDEBAR_W: u32 = 220;
const HEADER_H: u32 = 80;

pub(super) fn handle_click(wx: u32, wy: u32, ww: u32, wh: u32, cx: i32, cy: i32) -> bool {
    let (rx, ry) = ((cx - wx as i32) as u32, (cy - wy as i32) as u32);
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        drop(s);
        return super::click_locked::handle_locked_click(rx, ry, ww, wh);
    }
    drop(s);
    if rx < SIDEBAR_W {
        return super::click_overview::handle_sidebar_click(ry);
    }
    let (cw, ch) = (ww - SIDEBAR_W, wh - HEADER_H - 30);
    match get_view() {
        WalletView::Overview => {
            super::click_overview::handle_overview_click(rx - SIDEBAR_W, ry - HEADER_H, cw)
        }
        WalletView::Send => super::click_send::handle_send_click(rx - SIDEBAR_W, ry - HEADER_H, cw),
        WalletView::Stealth => {
            super::click_send::handle_stealth_click(rx - SIDEBAR_W, ry - HEADER_H, cw, ch)
        }
        WalletView::Settings => {
            super::click_send::handle_settings_click(rx - SIDEBAR_W, ry - HEADER_H, cw, ch)
        }
        WalletView::ZkSync => {
            super::click_zksync::handle_zksync_click(rx - SIDEBAR_W, ry - HEADER_H, cw)
        }
        WalletView::Staking => {
            super::staking::handle_staking_click(rx - SIDEBAR_W, ry - HEADER_H, cw)
        }
        _ => false,
    }
}

pub(super) fn handle_key(ch: u8) {
    super::keyboard::handle_key(ch);
}
pub(super) fn handle_special_key(key: SpecialKey) {
    super::keyboard::handle_special_key(key);
}
