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

use crate::graphics::window::state::TITLE_BAR_HEIGHT;
use super::state::*;
use super::{privacy, network, appearance, system, power};

pub fn handle_click(win_x: u32, win_y: u32, win_w: u32, click_x: i32, click_y: i32) -> bool {
    let content_y = win_y + TITLE_BAR_HEIGHT;

    if handle_sidebar_click(win_x, content_y, click_x, click_y) {
        return true;
    }

    let content_x = win_x + SIDEBAR_WIDTH;
    let content_w = win_w - SIDEBAR_WIDTH;
    let page = get_page();

    match page {
        PAGE_PRIVACY => privacy::handle_click(content_x, content_y, content_w, click_x, click_y),
        PAGE_NETWORK => network::handle_click(content_x, content_y, content_w, click_x, click_y),
        PAGE_APPEARANCE => appearance::handle_click(content_x, content_y + 45, content_w, click_x, click_y),
        PAGE_SYSTEM => system::handle_click(content_x, content_y, content_w, click_x, click_y),
        PAGE_POWER => power::handle_click(content_x, content_y, content_w, click_x, click_y),
        _ => false,
    }
}

fn handle_sidebar_click(win_x: u32, content_y: u32, click_x: i32, click_y: i32) -> bool {
    if click_x < win_x as i32 || click_x >= (win_x + SIDEBAR_WIDTH) as i32 {
        return false;
    }

    if click_y >= content_y as i32 + 40 && click_y < content_y as i32 + 40 + 175 {
        let tab_idx = ((click_y - content_y as i32 - 40) / 35) as u8;
        if tab_idx < PAGE_COUNT {
            set_page(tab_idx);
            return true;
        }
    }

    false
}
