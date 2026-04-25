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

use super::buttons::{draw_buttons, draw_clock_icon, DISPLAY_H, PADDING};
use super::numbers::{draw_number_large, draw_number_small};
use super::state::{CALC_DISPLAY, CALC_EXPR_OP, CALC_EXPR_VAL, CALC_NEW_INPUT, CALC_OPERATOR};
use super::{history, memory, scientific};
use crate::graphics::design_system::colors;
use crate::graphics::framebuffer::rounded_rect_blend;
use core::sync::atomic::Ordering;

pub(crate) fn draw_calculator(x: u32, y: u32, w: u32, h: u32) {
    rounded_rect_blend(x, y, w, h, 16, colors::GLASS_BG_DARK);
    draw_display(x, y, w);
    if memory::has_memory() {
        draw_memory_indicator(x + PADDING + 8, y + PADDING + 8);
    }
    draw_expression(x, y, w);
    draw_number_large(x + w - PADDING - 20, y + PADDING + 45, CALC_DISPLAY.load(Ordering::Relaxed));
    if scientific::is_scientific_mode() {
        super::render_scientific::draw_scientific_panel(
            x + PADDING,
            y + DISPLAY_H + PADDING + 8,
            w - PADDING * 2,
            150,
        );
        draw_buttons(x, y + 150, w, h - 150);
    } else {
        draw_buttons(x, y, w, h);
    }
    if history::is_visible() {
        super::render_history::draw_history_panel(x + w + 8, y, 200, h);
    }
}

fn draw_display(x: u32, y: u32, w: u32) {
    rounded_rect_blend(x + PADDING, y + PADDING, w - PADDING * 2, DISPLAY_H, 12, colors::GLASS_BG);
    draw_clock_icon(x + w - PADDING - 20, y + PADDING + 8);
}

fn draw_memory_indicator(x: u32, y: u32) {
    crate::graphics::font::draw_text(x, y, b"M", colors::ACCENT);
}

fn draw_expression(x: u32, y: u32, w: u32) {
    let expr_op = CALC_EXPR_OP.load(Ordering::Relaxed);
    if expr_op == 0 {
        return;
    }
    let expr_val = CALC_EXPR_VAL.load(Ordering::Relaxed);
    let mut expr_x = x + w - PADDING - 20;
    let expr_y = y + PADDING + 18;
    let current = CALC_DISPLAY.load(Ordering::Relaxed);
    if !CALC_NEW_INPUT.load(Ordering::Relaxed) || CALC_OPERATOR.load(Ordering::Relaxed) == 0 {
        expr_x = draw_number_small(expr_x, expr_y, current, colors::TEXT_SECONDARY);
        expr_x -= 16;
    }
    let op_ch = match expr_op {
        1 => b'+',
        2 => b'-',
        3 => 0xD7,
        4 => 0xF7,
        _ => b' ',
    };
    crate::graphics::font::draw_char(expr_x, expr_y, op_ch, colors::TEXT_SECONDARY);
    draw_number_small(expr_x - 16, expr_y, expr_val, colors::TEXT_SECONDARY);
}
