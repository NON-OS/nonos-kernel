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
use crate::graphics::framebuffer::{fill_rect, dimensions, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW};
use crate::graphics::font::draw_char;

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
    let dialog_w = 400u32;
    let dialog_h = 180u32;
    let x = (screen_w - dialog_w) / 2;
    let y = (screen_h - dialog_h) / 2;

    fill_rect(0, 0, screen_w, screen_h, 0x80000000);

    fill_rect(x, y, dialog_w, dialog_h, 0xFF1E2530);
    fill_rect(x, y, dialog_w, 1, 0xFF3D4550);
    fill_rect(x, y + dialog_h - 1, dialog_w, 1, 0xFF3D4550);
    fill_rect(x, y, 1, dialog_h, 0xFF3D4550);
    fill_rect(x + dialog_w - 1, y, 1, dialog_h, 0xFF3D4550);

    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);

    fill_rect(x, y, dialog_w, 35, 0xFF21262D);
    let icon_color = match dtype {
        DIALOG_WARNING => COLOR_YELLOW,
        DIALOG_ERROR => COLOR_RED,
        DIALOG_CONFIRM => COLOR_ACCENT,
        _ => COLOR_GREEN,
    };
    fill_rect(x + 12, y + 10, 16, 16, icon_color);

    // SAFETY: Read-only access to dialog title
    unsafe {
        if DIALOG_TITLE_LEN > 0 {
            draw_string(x + 36, y + 10, &DIALOG_TITLE[..DIALOG_TITLE_LEN], COLOR_TEXT_WHITE);
        }
    }

    // SAFETY: Read-only access to dialog message
    unsafe {
        if DIALOG_MESSAGE_LEN > 0 {
            let lines = (DIALOG_MESSAGE_LEN + 45) / 46;
            for line in 0..lines.min(3) {
                let start = line * 46;
                let end = (start + 46).min(DIALOG_MESSAGE_LEN);
                if start < DIALOG_MESSAGE_LEN {
                    draw_string(x + 20, y + 55 + (line as u32) * 18, &DIALOG_MESSAGE[start..end], 0xFFADBBC6);
                }
            }
        }
    }

    let btn_y = y + dialog_h - 45;

    match dtype {
        DIALOG_CONFIRM => {
            fill_rect(x + dialog_w / 2 - 90, btn_y, 80, 30, COLOR_GREEN);
            draw_string(x + dialog_w / 2 - 74, btn_y + 8, b"Yes", 0xFF0D1117);

            fill_rect(x + dialog_w / 2 + 10, btn_y, 80, 30, 0xFF4A5568);
            draw_string(x + dialog_w / 2 + 30, btn_y + 8, b"No", COLOR_TEXT_WHITE);
        }
        _ => {
            fill_rect(x + dialog_w / 2 - 40, btn_y, 80, 30, COLOR_ACCENT);
            draw_string(x + dialog_w / 2 - 16, btn_y + 8, b"OK", 0xFF0D1117);
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
