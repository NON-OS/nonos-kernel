//! Keyboard Driver with Multiple Layout Support

use crate::arch::x86_64::port::{inb, outb};
use crate::ui::event::{Event, publish, Pri};
use spin::Mutex;
use super::layouts::{Layout, get_ascii_mapping};

/// Keyboard state tracking with layout selection
#[derive(Clone, Copy)]
pub struct KeyboardState {
    pub shift_pressed: bool,
    pub ctrl_pressed: bool,
    pub alt_pressed: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
    pub extended: bool,
    pub layout: Layout,
}

impl KeyboardState {
    pub const fn new() -> Self {
        Self {
            shift_pressed: false,
            ctrl_pressed: false,
            alt_pressed: false,
            caps_lock: false,
            num_lock: true,
            scroll_lock: false,
            extended: false,
            layout: Layout::UsQwerty,
        }
    }
}

static KEYBOARD_STATE: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// Initialize keyboard controller (enables IRQ1)
pub fn init() {
    enable_keyboard_interrupt();
}

/// Set keyboard layout at runtime
pub fn set_layout(layout: Layout) {
    KEYBOARD_STATE.lock().layout = layout;
}

/// Get current keyboard layout
pub fn get_layout() -> Layout {
    KEYBOARD_STATE.lock().layout
}

/// Handle keyboard interrupt (IRQ1)
pub fn handle_keyboard_interrupt() {
    let scan_code = unsafe { inb(0x60) };
    let mut state = KEYBOARD_STATE.lock();

    // Extended scan code handling
    if scan_code == 0xE0 {
        state.extended = true;
        return;
    }

    let key_released = (scan_code & 0x80) != 0;
    let scan_code = scan_code & 0x7F;

    match scan_code {
        0x2A | 0x36 => state.shift_pressed = !key_released, // Shift
        0x1D => state.ctrl_pressed = !key_released,         // Ctrl
        0x38 => state.alt_pressed = !key_released,          // Alt
        0x3A if !key_released => state.caps_lock = !state.caps_lock, // Caps Lock
        0x45 if !key_released => state.num_lock = !state.num_lock,   // Num Lock
        0x46 if !key_released => state.scroll_lock = !state.scroll_lock, // Scroll Lock
        _ if !key_released => {
            // Regular keys, use selected layout
            let ascii_table = get_ascii_mapping(state.layout);
            let ascii = if state.shift_pressed || (state.caps_lock && scan_code >= 16 && scan_code <= 25) {
                ascii_table[scan_code as usize].to_ascii_uppercase()
            } else {
                ascii_table[scan_code as usize]
            };
            if ascii != 0 {
                publish(Event::KeyPress(ascii), Pri::Normal);
                let ch = [ascii];
                if let Ok(s) = core::str::from_utf8(&ch) {
                    crate::arch::x86_64::vga::print(s);
                }
            }
        }
        _ => {}
    }

    state.extended = false;
}

fn enable_keyboard_interrupt() {
    unsafe {
        let mut mask = inb(0x21);
        mask &= !0x02; // Enable IRQ1 (keyboard)
        outb(0x21, mask);
    }
}

/// Get current keyboard state
pub fn get_keyboard_state() -> KeyboardState {
    *KEYBOARD_STATE.lock()
}

/// Advanced key repeat handling
pub struct KeyRepeatManager {
    last_key: u8,
    repeat_count: u32,
    repeat_delay: u32,
}

impl KeyRepeatManager {
    pub const fn new() -> Self {
        Self {
            last_key: 0,
            repeat_count: 0,
            repeat_delay: 500, // 500ms initial delay
        }
    }

    pub fn handle_key(&mut self, key: u8) -> bool {
        if key == self.last_key {
            self.repeat_count += 1;
            if self.repeat_count > self.repeat_delay {
                return true;
            }
        } else {
            self.last_key = key;
            self.repeat_count = 0;
        }
        false
    }
}

static KEY_REPEAT: Mutex<KeyRepeatManager> = Mutex::new(KeyRepeatManager::new());

/// Key codes for keyboard events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
    Space, Enter, Escape, Backspace, Tab, Delete,
    Up, Down, Left, Right, Home, End, WordLeft, WordRight,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    Shift, Ctrl, Alt, CapsLock,
    Char(char),
    Unknown,
}

/// Get blocking keyboard event (stub)
pub fn get_event_blocking() -> Option<KeyCode> {
    None
}
