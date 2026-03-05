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

//! Unified keyboard input - wraps drivers/keyboard for the input subsystem.

use crate::drivers::keyboard as kbd_driver;

/// Initialize keyboard driver
pub fn init() {
    if let Err(_e) = kbd_driver::init_keyboard() {
        crate::sys::serial::println(b"[KBD] Driver init failed");
    } else {
        crate::sys::serial::println(b"[KBD] Driver initialized");
    }
}

/// Poll for a key scancode (non-blocking)
/// When interrupts are enabled, this returns None since the interrupt
/// handler consumes scancodes directly. Use read_char() instead.
pub fn poll() -> Option<u8> {
    // With interrupts enabled, data is already consumed by the ISR
    // This is kept for backward compatibility with polling-only mode
    kbd_driver::io::read_data_if_available()
}

/// Convert scancode to ASCII character
pub fn scancode_to_ascii(sc: u8) -> Option<u8> {
    // Use the driver's scancode processing
    kbd_driver::process_scancode(sc);
    // Try to read resulting character
    kbd_driver::read_char().map(|c| c as u8)
}

/// Poll for a character from the keyboard buffer (interrupt-driven)
/// This reads from the ring buffer filled by the interrupt handler
pub fn poll_char() -> Option<u8> {
    let result = kbd_driver::read_char().map(|c| c as u8);
    if let Some(ch) = result {
        crate::sys::serial::print(b"[INPUT] got char: ");
        crate::sys::serial::print(&[ch]);
        crate::sys::serial::println(b"");
    }
    result
}

/// Check if keyboard has data available
pub fn has_data() -> bool {
    kbd_driver::has_data()
}

/// Read a character from the keyboard buffer
pub fn read_char() -> Option<char> {
    kbd_driver::read_char()
}

/// Check if shift is pressed
pub fn is_shift_pressed() -> bool {
    kbd_driver::is_shift_pressed()
}

/// Check if ctrl is pressed
pub fn is_ctrl_pressed() -> bool {
    kbd_driver::is_ctrl_pressed()
}

/// Check if alt is pressed
pub fn is_alt_pressed() -> bool {
    kbd_driver::is_alt_pressed()
}

/// Get keyboard interface
pub fn get_keyboard() -> &'static kbd_driver::KeyboardInterface {
    kbd_driver::get_keyboard()
}

/// Poll for a special key event (arrows, home, end, etc.)
/// Returns Some(KeyEvent) if a special key was pressed
pub fn poll_event() -> Option<kbd_driver::KeyEvent> {
    kbd_driver::get_keyboard().read_event()
}

/// Re-export KeyEvent for convenience
pub use kbd_driver::KeyEvent;
