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

use crate::drivers::keyboard as kbd_driver;

pub fn init() {
    if let Err(_e) = kbd_driver::init_keyboard() {
        crate::sys::serial::println(b"[KBD] Driver init failed");
    } else {
        crate::sys::serial::println(b"[KBD] Driver initialized");
    }
}

pub fn poll() -> Option<u8> {
    kbd_driver::io::read_data_if_available()
}

pub fn scancode_to_ascii(sc: u8) -> Option<u8> {
    kbd_driver::process_scancode(sc);
    kbd_driver::read_char().map(|c| c as u8)
}

pub fn poll_char() -> Option<u8> {
    let result = kbd_driver::read_char().map(|c| c as u8);
    if let Some(ch) = result {
        crate::sys::serial::print(b"[INPUT] got char: ");
        crate::sys::serial::print(&[ch]);
        crate::sys::serial::println(b"");
    }
    result
}

pub fn has_data() -> bool {
    kbd_driver::has_data()
}

pub fn read_char() -> Option<char> {
    kbd_driver::read_char()
}

pub fn is_shift_pressed() -> bool {
    kbd_driver::is_shift_pressed()
}

pub fn is_ctrl_pressed() -> bool {
    kbd_driver::is_ctrl_pressed()
}

pub fn is_alt_pressed() -> bool {
    kbd_driver::is_alt_pressed()
}

pub fn get_keyboard() -> &'static kbd_driver::KeyboardInterface {
    kbd_driver::get_keyboard()
}

pub fn poll_event() -> Option<kbd_driver::KeyEvent> {
    kbd_driver::get_keyboard().read_event()
}

pub use kbd_driver::KeyEvent;
