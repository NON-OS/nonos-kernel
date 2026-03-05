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

//! Input subsystem (I2C HID, USB HID, and PS/2).

pub mod i2c_hid;
pub mod keyboard;
pub mod mouse;
pub mod usb_hid;

// Re-export PS/2 keyboard functions for backward compatibility
pub use keyboard::{
    init as keyboard_init, poll as keyboard_poll, scancode_to_ascii, poll_char,
    has_data, read_char, is_shift_pressed, is_ctrl_pressed, is_alt_pressed,
    get_keyboard, poll_event, KeyEvent,
};

// Re-export PS/2 mouse functions for backward compatibility
pub use mouse::{init as mouse_init, poll as mouse_poll, handle_interrupt};

/// Input source type
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputSource {
    PS2,
    USB,
    I2C,
}

/// Unified input manager that handles both USB and PS/2 devices
pub struct InputManager {
    input_source: InputSource,
}

impl InputManager {
    /// Create a new input manager with the best available input source
    pub fn detect() -> Self {
        let source = if i2c_hid::touchpad_available() {
            InputSource::I2C
        } else if usb_hid::is_available() {
            InputSource::USB
        } else {
            InputSource::PS2
        };

        Self { input_source: source }
    }

    /// Get the current input source
    pub fn source(&self) -> InputSource {
        self.input_source
    }
}

/// Poll for keyboard input from the best available source
/// Returns Some(ascii) if a key was pressed
pub fn poll_keyboard_unified() -> Option<u8> {
    // Try USB first if available
    if usb_hid::keyboard_available() {
        if let Some(key) = usb_hid::poll_keyboard() {
            return Some(key);
        }
    }

    // Fall back to PS/2 - read from ring buffer (filled by interrupt handler)
    keyboard::poll_char()
}

/// Poll for special key events (arrows, home, end, etc.)
/// Returns Some(KeyEvent) if a special key was pressed
pub fn poll_special_key() -> Option<KeyEvent> {
    keyboard::poll_event()
}

/// Poll for mouse input from the best available source.
///
/// Always returns true to allow the main loop to check for cursor
/// position changes. The actual position check happens in the main loop.
pub fn poll_mouse_unified() -> bool {
    // Poll I2C HID - this updates cursor position if touchpad data available
    i2c_hid::poll();

    // Poll USB HID if available
    if usb_hid::mouse_available() {
        usb_hid::poll_mouse();
    }

    // Always return true - let main loop handle position change detection
    true
}

/// Get current mouse position from the best available source
pub fn mouse_position_unified() -> (i32, i32) {
    // Use PS/2 mouse position when available (most laptops use PS/2 emulation)
    if mouse::is_available() {
        return mouse::position();
    }
    // Fall back to I2C HID
    i2c_hid::touchpad_position()
}

/// Check if left mouse button is pressed
pub fn left_button_pressed() -> bool {
    // Check PS/2 mouse first (most laptops use PS/2 emulation for touchpad clicks)
    if mouse::is_available() {
        return mouse::left_pressed();
    }
    // Fall back to USB HID
    if usb_hid::mouse_available() {
        return usb_hid::left_pressed();
    }
    false
}

/// Check if right mouse button is pressed
pub fn right_button_pressed() -> bool {
    // Check PS/2 mouse first (most laptops use PS/2 emulation for touchpad clicks)
    if mouse::is_available() {
        return mouse::right_pressed();
    }
    // Fall back to USB HID
    if usb_hid::mouse_available() {
        return usb_hid::right_pressed();
    }
    false
}

/// Set screen bounds for mouse movement
pub fn set_screen_bounds_unified(width: u32, height: u32) {
    mouse::set_screen_bounds(width, height);
    usb_hid::set_screen_bounds(width, height);
    i2c_hid::set_screen_bounds(width, height);
}
