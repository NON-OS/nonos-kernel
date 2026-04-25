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

use crate::graphics::design_system::colors;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::rounded_rect_blend;

const SCI_BTN_W: u32 = 48;
const SCI_BTN_H: u32 = 32;
const SCI_BTN_GAP: u32 = 4;
const SCI_PADDING: u32 = 8;

pub(crate) fn draw_scientific_panel(x: u32, y: u32, w: u32, h: u32) {
    rounded_rect_blend(x, y, w, h, 12, colors::GLASS_BG);
    let buttons: [[&[u8]; 4]; 4] = [
        [b"sin", b"cos", b"tan", b"DEG"],
        [b"ln", b"log", b"sqrt", b"x^2"],
        [b"x^y", b"e^x", b"1/x", b"("],
        [b"pi", b"e", b"!", b")"],
    ];
    let btn_start_y = y + SCI_PADDING;
    for (row, btns) in buttons.iter().enumerate() {
        for (col, label) in btns.iter().enumerate() {
            let bx = x + SCI_PADDING + col as u32 * (SCI_BTN_W + SCI_BTN_GAP);
            let by = btn_start_y + row as u32 * (SCI_BTN_H + SCI_BTN_GAP);
            draw_sci_button(bx, by, *label, false);
        }
    }
}

fn draw_sci_button(x: u32, y: u32, label: &[u8], active: bool) {
    let bg = if active { colors::GLASS_BG_ACTIVE } else { colors::GLASS_BG_LIGHT };
    rounded_rect_blend(x, y, SCI_BTN_W, SCI_BTN_H, 6, bg);
    let tx = x + (SCI_BTN_W - label.len() as u32 * 8) / 2;
    let ty = y + (SCI_BTN_H - 16) / 2;
    draw_text(tx, ty, label, colors::TEXT_PRIMARY);
}

#[allow(dead_code)]
pub(crate) fn sci_button_hit_test(
    panel_x: u32,
    panel_y: u32,
    click_x: i32,
    click_y: i32,
) -> Option<(usize, usize)> {
    let rel_x = click_x - panel_x as i32 - SCI_PADDING as i32;
    let rel_y = click_y - panel_y as i32 - SCI_PADDING as i32;
    if rel_x < 0 || rel_y < 0 {
        return None;
    }
    let col = rel_x as u32 / (SCI_BTN_W + SCI_BTN_GAP);
    let row = rel_y as u32 / (SCI_BTN_H + SCI_BTN_GAP);
    if col < 4 && row < 4 {
        Some((row as usize, col as usize))
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn get_scientific_width() -> u32 {
    SCI_PADDING * 2 + 4 * SCI_BTN_W + 3 * SCI_BTN_GAP
}
#[allow(dead_code)]
pub(crate) fn get_scientific_height() -> u32 {
    SCI_PADDING * 2 + 4 * SCI_BTN_H + 3 * SCI_BTN_GAP
}
