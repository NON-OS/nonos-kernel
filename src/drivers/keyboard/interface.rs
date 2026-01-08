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

use core::sync::atomic::{AtomicU64, Ordering};
use super::constants::{KBD_MAX_INTERRUPTS_PER_SEC, KBD_RATE_LIMIT_WINDOW_US, KBD_VECTOR};
use super::event::KeyEvent;
use super::io::{i8042_init_best_effort, read_data_if_available, send_eoi};
use super::scancode::{
    get_modifiers, has_data, has_event, is_alt_pressed, is_caps_lock_active, is_ctrl_pressed,
    is_shift_pressed, pending_char_count, process_scancode, read_char, read_event,
};

static ISR_WINDOW_START: AtomicU64 = AtomicU64::new(0);
static ISR_COUNT_IN_WINDOW: AtomicU64 = AtomicU64::new(0);
pub struct KeyboardInterface {
    pub initialized: bool,
}

impl KeyboardInterface {
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    #[inline]
    pub fn read_char(&self) -> Option<char> {
        read_char()
    }

    #[inline]
    pub fn has_data(&self) -> bool {
        has_data()
    }

    #[inline]
    pub fn read_event(&self) -> Option<KeyEvent> {
        read_event()
    }

    #[inline]
    pub fn has_event(&self) -> bool {
        has_event()
    }

    #[inline]
    pub fn get_modifiers(&self) -> u8 {
        get_modifiers()
    }

    #[inline]
    pub fn is_shift_pressed(&self) -> bool {
        is_shift_pressed()
    }

    #[inline]
    pub fn is_ctrl_pressed(&self) -> bool {
        is_ctrl_pressed()
    }

    #[inline]
    pub fn is_alt_pressed(&self) -> bool {
        is_alt_pressed()
    }

    #[inline]
    pub fn is_caps_lock_active(&self) -> bool {
        is_caps_lock_active()
    }

    #[inline]
    pub fn pending_char_count(&self) -> usize {
        pending_char_count()
    }

    pub fn read_line(&self, buffer: &mut [u8]) -> usize {
        let mut pos = 0;
        loop {
            if let Some(ch) = self.read_char() {
                if ch == '\n' || ch == '\r' {
                    break;
                }
                if ch == '\x08' {
                    if pos > 0 {
                        pos -= 1;
                    }
                } else if pos < buffer.len() {
                    buffer[pos] = ch as u8;
                    pos += 1;
                }
            } else {
                core::hint::spin_loop();
            }
        }
        pos
    }
}

static KEYBOARD_INTERFACE: KeyboardInterface = KeyboardInterface::new();

#[inline]
pub fn get_keyboard() -> &'static KeyboardInterface {
    &KEYBOARD_INTERFACE
}

fn keyboard_isr(_: crate::arch::x86_64::InterruptStackFrame) {
    let now = crate::arch::x86_64::time::tsc::elapsed_us();
    let window_start = ISR_WINDOW_START.load(Ordering::Relaxed);

    if now.saturating_sub(window_start) >= KBD_RATE_LIMIT_WINDOW_US {
        ISR_WINDOW_START.store(now, Ordering::Relaxed);
        ISR_COUNT_IN_WINDOW.store(1, Ordering::Relaxed);
    } else {
        let count = ISR_COUNT_IN_WINDOW.fetch_add(1, Ordering::Relaxed);
        if count >= KBD_MAX_INTERRUPTS_PER_SEC {
            send_eoi();
            return;
        }
    }

    if let Some(sc) = read_data_if_available() {
        process_scancode(sc);
    }
    send_eoi();
}

pub fn handle_keyboard_interrupt() {
    if let Some(sc) = read_data_if_available() {
        process_scancode(sc);
    }
}

pub fn init_keyboard() -> Result<(), &'static str> {
    crate::interrupts::register_interrupt_handler(KBD_VECTOR, keyboard_isr)?;
    i8042_init_best_effort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyboard_interface() {
        let kbd = get_keyboard();
        let _ = kbd.has_data();
        let _ = kbd.get_modifiers();
    }
}
