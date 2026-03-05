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

//! Keyboard abstraction for kernel UI.

#![cfg(feature = "ui")]

use spin::Mutex;

use crate::ui::event::{Event, KeyEvent, publish_event};

/// Keyboard driver trait to be implemented by arch/device drivers.
pub trait KeyboardDriver: Send + Sync {
    /// Poll for a scancode if available.
    fn poll_scancode(&self) -> Option<u8>;
}

static KEYBOARD_DRIVER: Mutex<Option<&'static dyn KeyboardDriver>> = Mutex::new(None);

/// Register keyboard driver. Returns Err if one is already registered.
pub fn register_keyboard_driver(driver: &'static dyn KeyboardDriver) -> Result<(), &'static str> {
    let mut g = KEYBOARD_DRIVER.lock();
    if g.is_some() {
        return Err("keyboard driver already registered");
    }
    *g = Some(driver);
    crate::log_info!("ui: keyboard driver registered");
    Ok(())
}

/// KeyCode (conservative subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Unknown,
    Char(u8),
    Enter,
    Backspace,
    Tab,
    Escape,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    F(u8),
}

/// Conservative scancode -> KeyCode mapping (production).
pub fn translate_scancode(scancode: u8, _pressed: bool) -> KeyCode {
    match scancode {
        0x1C => KeyCode::Enter,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x01 => KeyCode::Escape,
        0x48 => KeyCode::ArrowUp,
        0x50 => KeyCode::ArrowDown,
        0x4B => KeyCode::ArrowLeft,
        0x4D => KeyCode::ArrowRight,
        b'a'..=b'z' => KeyCode::Char(scancode),
        _ => KeyCode::Unknown,
    }
}

/// Poll driver and emit KeyEvent. Intended to be run in a kernel thread or timer.
pub fn poll_and_emit() {
    let g = KEYBOARD_DRIVER.lock();
    if let Some(driver) = *g {
        if let Some(sc) = driver.poll_scancode() {
            let pressed = true;
            let kev = KeyEvent { scancode: sc, pressed };
            if publish_event(Event::Key(kev)).is_err() {
                crate::log_warn!("ui: failed to publish key event");
            }
        }
    }
}

/// Initialize keyboard subsystem (no-op if driver not registered yet).
pub fn init_keyboard() {
    crate::log_info!("ui: keyboard subsystem initialized");
}
