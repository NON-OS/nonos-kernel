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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use crate::graphics::framebuffer::{fill_rect, put_pixel, dimensions, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW};
use crate::graphics::font::draw_char;

const COLOR_DIALOG_BG: u32 = 0xFF2C2C2E;
const COLOR_HEADER_BG: u32 = 0xFF3A3A3C;
const COLOR_BORDER: u32 = 0xFF48484A;
const COLOR_TEXT_DIM: u32 = 0xFF8E8E93;

fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + r - dx, y + r - dy, color);
                put_pixel(x + w - r + dx - 1, y + r - dy, color);
                put_pixel(x + r - dx, y + h - r + dy - 1, color);
                put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
            }
        }
    }
}

const MAX_MESSAGE_LEN: usize = 128;
const MAX_TITLE_LEN: usize = 32;

static DIALOG_ACTIVE: AtomicBool = AtomicBool::new(false);
static DIALOG_TYPE: AtomicU8 = AtomicU8::new(0);
static DIALOG_RESULT: AtomicU8 = AtomicU8::new(0);
static mut DIALOG_MESSAGE: [u8; MAX_MESSAGE_LEN] = [0u8; MAX_MESSAGE_LEN];
static mut DIALOG_MESSAGE_LEN: usize = 0;
static mut DIALOG_TITLE: [u8; MAX_TITLE_LEN] = [0u8; MAX_TITLE_LEN];
static mut DIALOG_TITLE_LEN: usize = 0;

pub const DIALOG_INFO: u8 = 0;
pub const DIALOG_WARNING: u8 = 1;
pub const DIALOG_ERROR: u8 = 2;
pub const DIALOG_CONFIRM: u8 = 3;
pub const DIALOG_INPUT: u8 = 4;

pub const RESULT_NONE: u8 = 0;
pub const RESULT_OK: u8 = 1;
pub const RESULT_CANCEL: u8 = 2;
pub const RESULT_YES: u8 = 3;
pub const RESULT_NO: u8 = 4;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub fn show_info(title: &[u8], message: &[u8]) {
    show_dialog(DIALOG_INFO, title, message);
}

pub fn show_warning(title: &[u8], message: &[u8]) {
    show_dialog(DIALOG_WARNING, title, message);
}

pub fn show_error(title: &[u8], message: &[u8]) {
    show_dialog(DIALOG_ERROR, title, message);
}

pub fn show_confirm(title: &[u8], message: &[u8]) {
    show_dialog(DIALOG_CONFIRM, title, message);
}

fn show_dialog(dtype: u8, title: &[u8], message: &[u8]) {
    let title_len = title.len().min(MAX_TITLE_LEN);
    let msg_len = message.len().min(MAX_MESSAGE_LEN);

    // SAFETY: Single-threaded dialog state access
    unsafe {
        for i in 0..title_len {
            DIALOG_TITLE[i] = title[i];
        }
        DIALOG_TITLE_LEN = title_len;

        for i in 0..msg_len {
            DIALOG_MESSAGE[i] = message[i];
        }
        DIALOG_MESSAGE_LEN = msg_len;
    }

    DIALOG_TYPE.store(dtype, Ordering::Relaxed);
    DIALOG_RESULT.store(RESULT_NONE, Ordering::Relaxed);
    DIALOG_ACTIVE.store(true, Ordering::Relaxed);
}

pub fn is_active() -> bool {
    DIALOG_ACTIVE.load(Ordering::Relaxed)
}

pub fn get_result() -> u8 {
    DIALOG_RESULT.load(Ordering::Relaxed)
}

pub fn close() {
    DIALOG_ACTIVE.store(false, Ordering::Relaxed);
    DIALOG_RESULT.store(RESULT_NONE, Ordering::Relaxed);
}

pub fn draw() {
    if !is_active() {
        return;
    }

    let (screen_w, screen_h) = dimensions();
    let dialog_w = 420u32;
    let dialog_h = 200u32;
    let x = (screen_w - dialog_w) / 2;
    let y = (screen_h - dialog_h) / 2;

    fill_rect(0, 0, screen_w, screen_h, 0x80000000);

    for shadow in 0..8u32 {
        let alpha = 30 - shadow * 3;
        draw_rounded_rect(x + shadow / 2, y + shadow + 4, dialog_w, dialog_h, 16, (alpha << 24) | 0x000000);
    }

    draw_rounded_rect(x, y, dialog_w, dialog_h, 16, COLOR_DIALOG_BG);

    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);

    for gy in 0..44u32 {
        let shade = 58 - (gy / 2) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        if gy < 16 {
            fill_rect(x + 16 - gy.min(16), y + gy, dialog_w - 32 + gy.min(16) * 2, 1, color);
        } else {
            fill_rect(x, y + gy, dialog_w, 1, color);
        }
    }
    fill_rect(x, y + 43, dialog_w, 1, COLOR_BORDER);

    let icon_color = match dtype {
        DIALOG_WARNING => COLOR_YELLOW,
        DIALOG_ERROR => COLOR_RED,
        DIALOG_CONFIRM => COLOR_ACCENT,
        _ => COLOR_GREEN,
    };

    draw_rounded_rect(x + 16, y + 10, 24, 24, 6, icon_color);

    let icon_char: u8 = match dtype {
        DIALOG_WARNING => b'!',
        DIALOG_ERROR => b'X',
        DIALOG_CONFIRM => b'?',
        _ => b'i',
    };
    draw_char(x + 24, y + 14, icon_char, 0xFF000000);

    unsafe {
        if DIALOG_TITLE_LEN > 0 {
            draw_string(x + 48, y + 14, &DIALOG_TITLE[..DIALOG_TITLE_LEN], COLOR_TEXT_WHITE);
        }
    }

    unsafe {
        if DIALOG_MESSAGE_LEN > 0 {
            let lines = (DIALOG_MESSAGE_LEN + 45) / 46;
            for line in 0..lines.min(3) {
                let start = line * 46;
                let end = (start + 46).min(DIALOG_MESSAGE_LEN);
                if start < DIALOG_MESSAGE_LEN {
                    draw_string(x + 24, y + 60 + (line as u32) * 20, &DIALOG_MESSAGE[start..end], COLOR_TEXT_DIM);
                }
            }
        }
    }

    let btn_y = y + dialog_h - 52;

    match dtype {
        DIALOG_CONFIRM => {
            draw_rounded_rect(x + dialog_w / 2 - 100, btn_y, 90, 36, 8, COLOR_GREEN);
            draw_string(x + dialog_w / 2 - 80, btn_y + 12, b"Yes", 0xFF000000);

            draw_rounded_rect(x + dialog_w / 2 + 10, btn_y, 90, 36, 8, COLOR_HEADER_BG);
            draw_string(x + dialog_w / 2 + 38, btn_y + 12, b"No", COLOR_TEXT_WHITE);
        }
        _ => {
            draw_rounded_rect(x + dialog_w / 2 - 45, btn_y, 90, 36, 8, COLOR_ACCENT);
            draw_string(x + dialog_w / 2 - 16, btn_y + 12, b"OK", 0xFF000000);
        }
    }
}

pub fn handle_click(mx: i32, my: i32) -> bool {
    if !is_active() {
        return false;
    }

    let (screen_w, screen_h) = dimensions();
    let dialog_w = 400u32;
    let dialog_h = 180u32;
    let x = ((screen_w - dialog_w) / 2) as i32;
    let y = ((screen_h - dialog_h) / 2) as i32;

    let btn_y = y + dialog_h as i32 - 45;
    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);

    match dtype {
        DIALOG_CONFIRM => {
            let yes_x = x + dialog_w as i32 / 2 - 90;
            if mx >= yes_x && mx < yes_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_YES, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }

            let no_x = x + dialog_w as i32 / 2 + 10;
            if mx >= no_x && mx < no_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_NO, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
        _ => {
            let ok_x = x + dialog_w as i32 / 2 - 40;
            if mx >= ok_x && mx < ok_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_OK, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
    }

    if mx >= x && mx < x + dialog_w as i32 && my >= y && my < y + dialog_h as i32 {
        return true;
    }

    false
}
