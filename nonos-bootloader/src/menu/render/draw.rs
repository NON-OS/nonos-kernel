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
use crate::display::gop::{draw_rect, fill_rect};
use crate::menu::types::MenuState;

const MENU_X: u32 = 300;
const MENU_Y: u32 = 200;
const MENU_W: u32 = 440;
const PAD: u32 = 24;
const ENTRY_H: u32 = 36;
const TITLE_H: u32 = 48;

const BG_PANEL: u32 = 0x0C0C14;
const BG_ENTRY: u32 = 0x14141C;
const BG_SELECT: u32 = 0x1E3850;
const BORDER_OUT: u32 = 0x2468A0;
const BORDER_IN: u32 = 0x183858;
const COL_TITLE: u32 = 0x50B0F0;
const COL_TEXT: u32 = 0xE0E0F0;
const COL_DIM: u32 = 0x606878;
const COL_ACCENT: u32 = 0x40C080;

pub fn render_menu(state: &MenuState) {
    if !state.visible {
        return;
    }

    let n = state.entries.len() as u32;
    let h = TITLE_H + (n * ENTRY_H) + 64 + (PAD * 2);

    fill_rect(MENU_X, MENU_Y, MENU_W, h, BG_PANEL);

    draw_rect(MENU_X, MENU_Y, MENU_W, h, BORDER_OUT);
    draw_rect(MENU_X + 2, MENU_Y + 2, MENU_W - 4, h - 4, BORDER_IN);

    fill_rect(MENU_X + PAD, MENU_Y + PAD, MENU_W - PAD * 2, 2, BORDER_OUT);

    draw_string(MENU_X + PAD, MENU_Y + PAD + 12, b"NONOS Secure Boot", COL_TITLE);

    let ey = MENU_Y + PAD + TITLE_H;
    for (i, action) in state.entries.iter().enumerate() {
        let y = ey + (i as u32 * ENTRY_H);
        let bg = if i == state.selected { BG_SELECT } else { BG_ENTRY };
        let ew = MENU_W - (PAD * 2);

        fill_rect(MENU_X + PAD, y, ew, ENTRY_H - 4, bg);

        if i == state.selected {
            fill_rect(MENU_X + PAD, y, 4, ENTRY_H - 4, COL_ACCENT);
            draw_string(MENU_X + PAD + 16, y + 10, action.label().as_bytes(), COL_TEXT);
        } else {
            draw_string(MENU_X + PAD + 16, y + 10, action.label().as_bytes(), COL_DIM);
        }
    }

    let hy = ey + (n * ENTRY_H) + 16;
    draw_string(MENU_X + PAD, hy, b"[Up/Down] Navigate", COL_DIM);
    draw_string(MENU_X + PAD + 180, hy, b"[Enter] Select", COL_DIM);
    draw_string(MENU_X + PAD, hy + 20, b"[Esc] Quick Boot (Standard)", COL_DIM);
}
