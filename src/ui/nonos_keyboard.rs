//! Keyboard abstraction for kernel UI.

#![cfg(feature = "ui")]

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::ui::nonos_event::{Event, KeyEvent, publish_event};

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
fn translate_scancode(scancode: u8, _pressed: bool) -> KeyCode {
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
