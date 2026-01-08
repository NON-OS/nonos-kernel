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

use super::constants::*;
use super::event::KeyEvent;
use super::io::update_leds;
use super::ring::{SpscEvtRing, SpscU8Ring};
use core::sync::atomic::{AtomicBool, Ordering};

static SHIFT: AtomicBool = AtomicBool::new(false);
static CTRL: AtomicBool = AtomicBool::new(false);
static ALT: AtomicBool = AtomicBool::new(false);
static CAPS: AtomicBool = AtomicBool::new(false);
static EXTENDED: AtomicBool = AtomicBool::new(false);

// SAFETY: SpscU8Ring uses atomic operations for head/tail synchronization.
// There is exactly ONE producer (keyboard interrupt handler) and ONE consumer
// (input reading from main context). Push and pop operations are lock-free
// and wait-free. The interrupt handler is non-reentrant on x86.
static mut CHAR_RING: SpscU8Ring<CHAR_RING_SIZE> = SpscU8Ring::new();

// SAFETY: Same invariants as CHAR_RING - single producer (interrupt),
// single consumer (main thread), with atomic synchronization.
static mut EVT_RING: SpscEvtRing<EVT_RING_SIZE> = SpscEvtRing::new();

pub fn process_scancode(sc: u8) {
    if sc == SC_EXT_E0 || sc == SC_EXT_E1 {
        EXTENDED.store(true, Ordering::Relaxed);
        return;
    }

    let is_break = (sc & SC_BREAK_BIT) != 0;
    let code = sc & 0x7F;
    match code {
        SC_LSHIFT | SC_RSHIFT => {
            SHIFT.store(!is_break, Ordering::Relaxed);
            return;
        }
        SC_LCTRL => {
            CTRL.store(!is_break, Ordering::Relaxed);
            return;
        }
        SC_LALT => {
            ALT.store(!is_break, Ordering::Relaxed);
            return;
        }
        SC_CAPSLOCK => {
            if !is_break {
                let old = CAPS.load(Ordering::Relaxed);
                CAPS.store(!old, Ordering::Relaxed);
                update_leds(!old, false, false);
            }
            return;
        }
        _ => {}
    }

    if is_break {
        return;
    }

    if EXTENDED.swap(false, Ordering::Relaxed) {
        if let Some(event) = extended_to_event(code) {
            // SAFETY: Called from interrupt handler (single producer).
            unsafe {
                EVT_RING.push_evt(event);
            }
        }
        return;
    }

    let shift = SHIFT.load(Ordering::Relaxed);
    let caps = CAPS.load(Ordering::Relaxed);
    let ch_opt = if shift {
        SHIFTED.get(code as usize).copied().flatten()
    } else {
        NORMAL.get(code as usize).copied().flatten()
    };

    if let Some(mut ch) = ch_opt {
        if ch.is_ascii_alphabetic() {
            let upper = shift ^ caps;
            ch = if upper {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            };
        }
        // SAFETY: Called from interrupt handler (single producer).
        unsafe {
            CHAR_RING.push(ch);
        }
    }
}

fn extended_to_event(code: u8) -> Option<KeyEvent> {
    match code {
        SC_EXT_UP => Some(KeyEvent::Up),
        SC_EXT_DOWN => Some(KeyEvent::Down),
        SC_EXT_LEFT => Some(KeyEvent::Left),
        SC_EXT_RIGHT => Some(KeyEvent::Right),
        SC_EXT_HOME => Some(KeyEvent::Home),
        SC_EXT_END => Some(KeyEvent::End),
        SC_EXT_PGUP => Some(KeyEvent::PageUp),
        SC_EXT_PGDN => Some(KeyEvent::PageDown),
        SC_EXT_INSERT => Some(KeyEvent::Insert),
        SC_EXT_DELETE => Some(KeyEvent::Delete),
        _ => None,
    }
}

#[inline]
pub fn read_char() -> Option<char> {
    // SAFETY: Single consumer (main thread).
    unsafe { CHAR_RING.pop().map(|b| b as char) }
}

#[inline]
pub fn has_data() -> bool {
    // SAFETY: Read-only operation.
    unsafe { !CHAR_RING.is_empty() }
}

#[inline]
pub fn read_event() -> Option<KeyEvent> {
    // SAFETY: Single consumer (main thread).
    unsafe { EVT_RING.pop_evt() }
}

#[inline]
pub fn has_event() -> bool {
    // SAFETY: Read-only operation.
    unsafe { !EVT_RING.is_empty() }
}

#[inline]
pub fn get_modifiers() -> u8 {
    let mut mods = 0;
    if SHIFT.load(Ordering::Relaxed) {
        mods |= 0x01;
    }
    if CTRL.load(Ordering::Relaxed) {
        mods |= 0x02;
    }
    if ALT.load(Ordering::Relaxed) {
        mods |= 0x04;
    }
    if CAPS.load(Ordering::Relaxed) {
        mods |= 0x08;
    }
    mods
}

#[inline]
pub fn is_shift_pressed() -> bool {
    SHIFT.load(Ordering::Relaxed)
}

#[inline]
pub fn is_ctrl_pressed() -> bool {
    CTRL.load(Ordering::Relaxed)
}

#[inline]
pub fn is_alt_pressed() -> bool {
    ALT.load(Ordering::Relaxed)
}

#[inline]
pub fn is_caps_lock_active() -> bool {
    CAPS.load(Ordering::Relaxed)
}

#[inline]
pub fn pending_char_count() -> usize {
    // SAFETY: Read-only operation.
    unsafe { CHAR_RING.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modifier_bitmask() {
        SHIFT.store(false, Ordering::Relaxed);
        CTRL.store(false, Ordering::Relaxed);
        ALT.store(false, Ordering::Relaxed);
        CAPS.store(false, Ordering::Relaxed);
        assert_eq!(get_modifiers(), 0);
        SHIFT.store(true, Ordering::Relaxed);
        assert_eq!(get_modifiers(), 0x01);
        CTRL.store(true, Ordering::Relaxed);
        assert_eq!(get_modifiers(), 0x03);
        ALT.store(true, Ordering::Relaxed);
        assert_eq!(get_modifiers(), 0x07);
        CAPS.store(true, Ordering::Relaxed);
        assert_eq!(get_modifiers(), 0x0F);
        SHIFT.store(false, Ordering::Relaxed);
        CTRL.store(false, Ordering::Relaxed);
        ALT.store(false, Ordering::Relaxed);
        CAPS.store(false, Ordering::Relaxed);
    }

    #[test]
    fn test_extended_to_event() {
        assert_eq!(extended_to_event(SC_EXT_UP), Some(KeyEvent::Up));
        assert_eq!(extended_to_event(SC_EXT_DOWN), Some(KeyEvent::Down));
        assert_eq!(extended_to_event(SC_EXT_LEFT), Some(KeyEvent::Left));
        assert_eq!(extended_to_event(SC_EXT_RIGHT), Some(KeyEvent::Right));
        assert_eq!(extended_to_event(0xFF), None);
    }
}
