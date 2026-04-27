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

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

static SHIFT: AtomicBool = AtomicBool::new(false);
static CTRL: AtomicBool = AtomicBool::new(false);
static ALT: AtomicBool = AtomicBool::new(false);
static CAPS_LOCK: AtomicBool = AtomicBool::new(false);

static KEYMAP: Mutex<[u8; 128]> = Mutex::new([0; 128]);

#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub scancode: u8,
    pub pressed: bool,
    pub character: Option<char>,
}

pub fn process_key(scancode: u8) -> Option<KeyEvent> {
    let pressed = (scancode & 0x80) == 0;
    let code = scancode & 0x7F;
    match code {
        0x2A | 0x36 => {
            SHIFT.store(pressed, Ordering::SeqCst);
            return None;
        }
        0x1D => {
            CTRL.store(pressed, Ordering::SeqCst);
            return None;
        }
        0x38 => {
            ALT.store(pressed, Ordering::SeqCst);
            return None;
        }
        0x3A if pressed => {
            CAPS_LOCK.fetch_xor(true, Ordering::SeqCst);
            return None;
        }
        _ => {}
    }
    if !pressed {
        return None;
    }
    let character = scancode_to_char(code);
    if let Some(c) = character {
        super::console_input(c as u8);
    }
    Some(KeyEvent { scancode, pressed, character })
}

fn scancode_to_char(code: u8) -> Option<char> {
    let shift = SHIFT.load(Ordering::SeqCst);
    let caps = CAPS_LOCK.load(Ordering::SeqCst);
    let ctrl = CTRL.load(Ordering::SeqCst);
    let base = match code {
        0x02..=0x0A => {
            let c = b"123456789"[(code - 0x02) as usize];
            if shift {
                b"!@#$%^&*("[c as usize - b'1' as usize]
            } else {
                c
            }
        }
        0x0B => {
            if shift {
                b')'
            } else {
                b'0'
            }
        }
        0x10..=0x19 => {
            let c = b"qwertyuiop"[(code - 0x10) as usize];
            if shift ^ caps {
                c - 32
            } else {
                c
            }
        }
        0x1E..=0x26 => {
            let c = b"asdfghjkl"[(code - 0x1E) as usize];
            if shift ^ caps {
                c - 32
            } else {
                c
            }
        }
        0x2C..=0x32 => {
            let c = b"zxcvbnm"[(code - 0x2C) as usize];
            if shift ^ caps {
                c - 32
            } else {
                c
            }
        }
        0x39 => b' ',
        0x1C => b'\n',
        0x0E => 0x7F,
        0x0F => b'\t',
        0x33 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        0x34 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        0x35 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        _ => return None,
    };
    if ctrl && base >= b'a' && base <= b'z' {
        return Some((base - b'a' + 1) as char);
    }
    Some(base as char)
}

pub fn set_keymap(keymap: &[u8; 128]) {
    *KEYMAP.lock() = *keymap;
}
