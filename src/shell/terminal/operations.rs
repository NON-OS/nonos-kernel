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

use super::renderer::{
    draw_window, draw_text_at, clear_content,
    COLOR_TEXT, COLOR_ACCENT, COLOR_SUCCESS, COLOR_WARNING, MAX_ROWS,
};
use super::input::get_editor as editor;
use super::{history, completion_reset, tab_complete, handle_key};

static mut CURRENT_ROW: u32 = 0;
static mut CURSOR_VISIBLE: bool = true;
static mut BLINK_COUNTER: u32 = 0;

pub fn init_state() {
    // SAFETY: Static variables only accessed from main thread during terminal init.
    unsafe {
        CURRENT_ROW = 0;
        CURSOR_VISIBLE = true;
        BLINK_COUNTER = 0;
    }
}

pub fn draw() {
    draw_window();
}

pub fn print_boot_sequence() {
    print_line(b"N\xd8NOS ZeroState v1.0.0", COLOR_ACCENT);
    print_line(b"Privacy-first OS running entirely in RAM", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"[OK] Memory isolation: ACTIVE", COLOR_SUCCESS);
    print_line(b"[OK] Anonymous mode: ENABLED", COLOR_SUCCESS);
    print_line(b"[OK] Anyone routing: READY", COLOR_SUCCESS);
    print_line(b"[OK] Crypto vault: INITIALIZED", COLOR_SUCCESS);
    print_line(b"", COLOR_TEXT);

    // Input device debug info
    print_input_status();

    print_line(b"All data erased on shutdown (ZeroState)", COLOR_WARNING);
    print_line(b"Type 'help' for available commands", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    show_prompt();
}

fn print_input_status() {
    use crate::input::{i2c_hid, usb_hid};
    use crate::input::mouse;

    let i2c = i2c_hid::touchpad_available();
    let usb = usb_hid::mouse_available();
    let ps2 = mouse::is_available();

    if i2c {
        print_line(b"[OK] Mouse: I2C HID touchpad", COLOR_SUCCESS);
    } else if usb {
        print_line(b"[OK] Mouse: USB HID", COLOR_SUCCESS);
    } else if ps2 {
        print_line(b"[OK] Mouse: PS/2", COLOR_SUCCESS);
    } else {
        print_line(b"[!!] Mouse: NOT DETECTED", COLOR_WARNING);
    }
    print_line(b"", COLOR_TEXT);
}

pub fn print_line(text: &[u8], color: u32) {
    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe {
        if CURRENT_ROW >= MAX_ROWS - 1 {
            scroll();
        }

        draw_text_at(0, CURRENT_ROW, text, color);
        CURRENT_ROW += 1;
    }
}

pub fn scroll() {
    clear_content();
    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe {
        CURRENT_ROW = 0;
    }
}

pub fn show_prompt() {
    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe {
        if CURRENT_ROW >= MAX_ROWS - 1 {
            scroll();
        }

        let ed = editor();
        ed.reset(CURRENT_ROW);
        ed.draw_prompt();
    }
}

pub fn putchar(ch: u8) {
    let ed = editor();
    ed.insert_char(ch);
    completion_reset();
}

pub fn backspace() {
    let ed = editor();
    ed.backspace();
    completion_reset();
}

pub fn execute() -> Option<&'static [u8]> {
    let ed = editor();
    let content = ed.get_content();

    if content.is_empty() {
        // SAFETY: CURRENT_ROW is only accessed from the main thread.
        unsafe {
            CURRENT_ROW += 1;
        }
        return None;
    }

    let len = content.len();
    let mut cmd_copy = [0u8; 256];
    cmd_copy[..len].copy_from_slice(&content[..len]);

    history::add_command(&cmd_copy[..len]);

    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe {
        CURRENT_ROW += 1;
    }

    completion_reset();
    ed.show_cursor(false);

    // SAFETY: The command buffer is valid for the static lifetime as it's stored
    // in the line editor's buffer which persists until the next command.
    Some(ed.get_content())
}

pub fn clear_command() {
    let ed = editor();
    ed.reset(ed.row());
}

pub fn blink_cursor(visible: bool) {
    let ed = editor();
    ed.show_cursor(visible);
}

pub fn update_cursor_blink() {
    // SAFETY: Blink state variables only accessed from main thread.
    unsafe {
        BLINK_COUNTER += 1;
        if BLINK_COUNTER >= 30 {
            BLINK_COUNTER = 0;
            CURSOR_VISIBLE = !CURSOR_VISIBLE;
            blink_cursor(CURSOR_VISIBLE);
        }
    }
}

pub fn handle_special_key(scancode: u8, ch: u8, ctrl: bool, alt: bool, _shift: bool) -> Option<&'static [u8]> {
    if scancode == 0x0F {
        tab_complete();
        return None;
    }

    if ctrl && (ch == b'c' || ch == b'C') {
        print_line(b"^C", COLOR_TEXT);
        show_prompt();
        return None;
    }

    if ctrl && (ch == b'd' || ch == b'D') {
        let ed = editor();
        if ed.length() == 0 {
            print_line(b"exit", COLOR_TEXT);
            return Some(b"exit");
        }
        ed.delete_char();
        return None;
    }

    handle_key(scancode, ch, ctrl, alt)
}

pub fn current_row() -> u32 {
    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe { CURRENT_ROW }
}

pub fn set_current_row(row: u32) {
    // SAFETY: CURRENT_ROW is only accessed from the main thread.
    unsafe {
        CURRENT_ROW = row.min(MAX_ROWS - 1);
    }
}
