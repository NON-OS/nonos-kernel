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

use super::graphics_manager;
use crate::input::{KeyEvent, poll_keyboard_unified, poll_special_key, poll_mouse_unified, mouse_position_unified, left_button_pressed, right_button_pressed, keyboard};

static mut MOUSE_X: i32 = 400;
static mut MOUSE_Y: i32 = 300;

pub fn process_keyboard_events() {
    if let Some(ch) = poll_keyboard_unified() {
        handle_char_input(ch);
    }

    if let Some(special_key) = poll_special_key() {
        handle_special_key(special_key);
    }
}

pub fn process_mouse_events() {
    let (x, y) = mouse_position_unified();
    let left_pressed = left_button_pressed();
    let right_pressed = right_button_pressed();

    let old_x = unsafe { MOUSE_X };
    let old_y = unsafe { MOUSE_Y };

    if x != old_x || y != old_y {
        unsafe {
            MOUSE_X = x;
            MOUSE_Y = y;
        }
        update_cursor_position(x, y);
    }

    if left_pressed {
        graphics_manager::handle_mouse_click(x, y, 1);
    }

    if right_pressed {
        graphics_manager::handle_mouse_click(x, y, 2);
    }
}

fn handle_char_input(ch: u8) {
    match ch {
        b'0'..=b'9' => handle_number_key(ch - b'0'),
        b'\t' => handle_tab_key(),
        b'\n' | b'\r' => handle_enter_key(),
        b' ' => handle_space_key(),
        0x1B => handle_escape_key(),
        _ => handle_other_char(ch),
    }
}

fn handle_special_key(key: KeyEvent) {
    match key {
        KeyEvent::Up => handle_arrow_key("Up"),
        KeyEvent::Down => handle_arrow_key("Down"),
        KeyEvent::Left => handle_arrow_key("Left"),
        KeyEvent::Right => handle_arrow_key("Right"),
        KeyEvent::Home => handle_nav_key("Home"),
        KeyEvent::End => handle_nav_key("End"),
        KeyEvent::PageUp => handle_nav_key("PageUp"),
        KeyEvent::PageDown => handle_nav_key("PageDown"),
        KeyEvent::Delete => handle_nav_key("Delete"),
        KeyEvent::Backspace => handle_nav_key("Backspace"),
        KeyEvent::Enter => handle_enter_key(),
        KeyEvent::Escape => handle_escape_key(),
    }
}


fn handle_number_key(number: u8) {
    crate::sys::serial::print(b"[DESKTOP] Number key: ");
    crate::sys::serial::print_dec(number as u64);
    crate::sys::serial::println(b"");
}

fn handle_other_char(ch: u8) {
    crate::sys::serial::print(b"[DESKTOP] Char: ");
    crate::sys::serial::print_dec(ch as u64);
    crate::sys::serial::println(b"");
}

fn handle_arrow_key(direction: &str) {
    crate::sys::serial::print(b"[DESKTOP] Arrow key: ");
    crate::sys::serial::println(direction.as_bytes());
}

fn handle_nav_key(key_name: &str) {
    crate::sys::serial::print(b"[DESKTOP] Nav key: ");
    crate::sys::serial::println(key_name.as_bytes());
}

fn handle_tab_key() {
    crate::sys::serial::println(b"[DESKTOP] Tab key");
}

fn handle_enter_key() {
    crate::sys::serial::println(b"[DESKTOP] Enter key");
}

fn handle_space_key() {
    crate::sys::serial::println(b"[DESKTOP] Space key");
}

fn handle_escape_key() {
    crate::sys::serial::println(b"[DESKTOP] Escape key");
}


fn update_cursor_position(x: i32, y: i32) {
    crate::graphics::cursor::erase();
    crate::graphics::cursor::set_position(x as u32, y as u32);
    crate::graphics::cursor::draw();
}

pub fn get_mouse_position() -> (i32, i32) {
    unsafe { (MOUSE_X, MOUSE_Y) }
}