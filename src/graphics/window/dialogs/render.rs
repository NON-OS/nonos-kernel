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

use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{dimensions, fill_rect};
use core::sync::atomic::Ordering;

const DIALOG_W: u32 = 420;
const DIALOG_H: u32 = 200;
const INPUT_DIALOG_H: u32 = 240;

pub(crate) fn draw() {
    if !is_active() {
        return;
    }
    let (sw, sh) = dimensions();
    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);
    let h = if dtype == DIALOG_INPUT { INPUT_DIALOG_H } else { DIALOG_H };
    let x = (sw - DIALOG_W) / 2;
    let y = (sh - h) / 2;

    fill_rect(0, 0, sw, sh, 0x80000000);
    for shadow in 0..8u32 {
        primitives::rounded_rect(
            x + shadow / 2,
            y + shadow + 4,
            DIALOG_W,
            h,
            16,
            (30 - shadow * 3) << 24,
        );
    }
    primitives::rounded_rect(x, y, DIALOG_W, h, 16, BG_ELEVATED);

    draw_header(x, y, DIALOG_W);
    draw_icon(x, y, dtype);
    draw_title_and_message(x, y);

    if dtype == DIALOG_INPUT {
        draw_input_field(x, y);
        draw_input_buttons(x, y);
    } else {
        draw_buttons(x, y, dtype);
    }
}

fn draw_header(x: u32, y: u32, w: u32) {
    for gy in 0..44u32 {
        let shade = 58 - (gy / 2) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        let inset = if gy < 16 { 16 - gy } else { 0 };
        fill_rect(x + inset, y + gy, w - inset * 2, 1, color);
    }
    fill_rect(x, y + 43, w, 1, BORDER_DEFAULT);
}

fn draw_icon(x: u32, y: u32, dtype: u8) {
    let color = match dtype {
        DIALOG_WARNING => WARNING,
        DIALOG_ERROR => ERROR,
        DIALOG_CONFIRM => ACCENT,
        _ => SUCCESS,
    };
    primitives::rounded_rect(x + 16, y + 10, 24, 24, 6, color);
    let ch = match dtype {
        DIALOG_WARNING => b'!',
        DIALOG_ERROR => b'X',
        DIALOG_CONFIRM => b'?',
        _ => b'i',
    };
    draw_char(x + 24, y + 14, ch, TEXT_INVERSE);
}

fn draw_title_and_message(x: u32, y: u32) {
    unsafe {
        if DIALOG_TITLE_LEN > 0 {
            text::draw(x + 48, y + 14, &DIALOG_TITLE[..DIALOG_TITLE_LEN], TEXT_PRIMARY);
        }
        if DIALOG_MESSAGE_LEN > 0 {
            let lines = (DIALOG_MESSAGE_LEN + 45) / 46;
            for line in 0..lines.min(3) {
                let start = line * 46;
                let end = (start + 46).min(DIALOG_MESSAGE_LEN);
                if start < DIALOG_MESSAGE_LEN {
                    text::draw(
                        x + 24,
                        y + 60 + (line as u32) * 20,
                        &DIALOG_MESSAGE[start..end],
                        TEXT_SECONDARY,
                    );
                }
            }
        }
    }
}

fn draw_buttons(x: u32, y: u32, dtype: u8) {
    let btn_y = y + DIALOG_H - 52;
    match dtype {
        DIALOG_CONFIRM => {
            primitives::rounded_rect(x + DIALOG_W / 2 - 100, btn_y, 90, 36, 8, SUCCESS);
            text::draw(x + DIALOG_W / 2 - 80, btn_y + 12, b"Yes", TEXT_INVERSE);
            primitives::rounded_rect(x + DIALOG_W / 2 + 10, btn_y, 90, 36, 8, BG_SURFACE);
            text::draw(x + DIALOG_W / 2 + 38, btn_y + 12, b"No", TEXT_PRIMARY);
        }
        _ => {
            primitives::rounded_rect(x + DIALOG_W / 2 - 45, btn_y, 90, 36, 8, ACCENT);
            text::draw(x + DIALOG_W / 2 - 16, btn_y + 12, b"OK", TEXT_INVERSE);
        }
    }
}

fn draw_input_field(x: u32, y: u32) {
    let input_x = x + 24;
    let input_y = y + 120;
    let input_w = DIALOG_W - 48;
    let input_h = 40u32;

    primitives::rounded_rect(input_x, input_y, input_w, input_h, 8, BG_INPUT);
    primitives::rounded_rect(input_x, input_y, input_w, input_h, 8, BORDER_FOCUS);

    let input_len = DIALOG_INPUT_LEN.load(Ordering::Relaxed);
    unsafe {
        if input_len > 0 {
            text::draw(input_x + 12, input_y + 14, &DIALOG_INPUT_BUF[..input_len], TEXT_PRIMARY);
        }
    }

    let cursor_x = input_x + 12 + (input_len as u32) * 8;
    fill_rect(cursor_x, input_y + 10, 2, 20, ACCENT);
}

fn draw_input_buttons(x: u32, y: u32) {
    let btn_y = y + INPUT_DIALOG_H - 52;

    primitives::rounded_rect(x + DIALOG_W / 2 - 100, btn_y, 90, 36, 8, SUCCESS);
    text::draw(x + DIALOG_W / 2 - 85, btn_y + 12, b"Create", TEXT_INVERSE);

    primitives::rounded_rect(x + DIALOG_W / 2 + 10, btn_y, 90, 36, 8, BG_SURFACE);
    text::draw(x + DIALOG_W / 2 + 25, btn_y + 12, b"Cancel", TEXT_PRIMARY);
}
