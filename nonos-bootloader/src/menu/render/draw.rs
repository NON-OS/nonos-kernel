// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::font::draw_string;
use crate::display::gop::fill_rect;
use crate::menu::types::MenuState;

const MENU_X: u32 = 100;
const MENU_Y: u32 = 200;
const ENTRY_HEIGHT: u32 = 32;
const ENTRY_WIDTH: u32 = 400;
const BG_COLOR: u32 = 0x202028;
const FG_COLOR: u32 = 0xC8C8DC;
const SELECTED_BG: u32 = 0x3C5078;
const TITLE_COLOR: u32 = 0x64B4FF;

pub fn render_menu(state: &MenuState) {
    if !state.visible {
        return;
    }

    draw_string(MENU_X, MENU_Y - 40, b"NONOS Boot Menu", TITLE_COLOR);

    for (i, action) in state.entries.iter().enumerate() {
        let y = MENU_Y + (i as u32 * ENTRY_HEIGHT);
        let bg = if i == state.selected { SELECTED_BG } else { BG_COLOR };

        fill_rect(MENU_X, y, ENTRY_WIDTH, ENTRY_HEIGHT - 2, bg);
        draw_string(MENU_X + 8, y + 8, action.label().as_bytes(), FG_COLOR);
    }

    draw_string(
        MENU_X,
        MENU_Y + (state.entries.len() as u32 * ENTRY_HEIGHT) + 16,
        b"Arrows: select  Enter: confirm  Esc: fast boot",
        FG_COLOR,
    );
}
