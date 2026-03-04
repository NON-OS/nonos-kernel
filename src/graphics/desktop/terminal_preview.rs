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

use crate::graphics::framebuffer::{fill_rect, COLOR_TERMINAL_BG, COLOR_PANEL, COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_text;
use super::constants::MENU_BAR_HEIGHT;

const TERM_WIDTH: u32 = 520;
const TERM_HEIGHT: u32 = 420;
const TITLE_HEIGHT: u32 = 28;

pub fn draw(screen_w: u32) {
    let term_x = screen_w - TERM_WIDTH - 40;
    let term_y = MENU_BAR_HEIGHT + 40;

    fill_rect(term_x, term_y, TERM_WIDTH, TERM_HEIGHT, COLOR_TERMINAL_BG);
    fill_rect(term_x, term_y, TERM_WIDTH, TITLE_HEIGHT, COLOR_PANEL);

    let btn_y = term_y + 9;
    fill_rect(term_x + 12, btn_y, 10, 10, COLOR_RED);
    fill_rect(term_x + 28, btn_y, 10, 10, COLOR_YELLOW);
    fill_rect(term_x + 44, btn_y, 10, 10, COLOR_GREEN);

    draw_text(term_x + 60, term_y + 8, b"N\xd8NOS Terminal", COLOR_TEXT_WHITE);
}
