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

use super::constants::*;
use super::scancode::{hid_to_ascii, KEY_CAPS_LOCK, KEY_ERR_ROLLOVER, KEY_NONE};
use alloc::collections::VecDeque;
use spin::Mutex;

const KEY_BUFFER_SIZE: usize = 64;

pub struct KeyboardState {
    modifiers: u8,
    leds: u8,
    prev_keys: [u8; 6],
    buffer: VecDeque<KeyEvent>,
    caps_lock: bool,
    num_lock: bool,
    scroll_lock: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub scancode: u8,
    pub ascii: Option<u8>,
    pub pressed: bool,
    pub modifiers: u8,
}

static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

impl KeyboardState {
    pub const fn new() -> Self {
        Self {
            modifiers: 0,
            leds: 0,
            prev_keys: [0; 6],
            buffer: VecDeque::new(),
            caps_lock: false,
            num_lock: false,
            scroll_lock: false,
        }
    }

    pub fn process_report(&mut self, report: &[u8; 8]) {
        self.modifiers = report[0];
        let current_keys: [u8; 6] =
            [report[2], report[3], report[4], report[5], report[6], report[7]];
        for key in current_keys {
            if key == KEY_NONE || key == KEY_ERR_ROLLOVER {
                continue;
            }
            if !self.prev_keys.contains(&key) {
                self.handle_key_press(key);
            }
        }
        let prev = self.prev_keys;
        for key in prev {
            if key == KEY_NONE {
                continue;
            }
            if !current_keys.contains(&key) {
                self.handle_key_release(key);
            }
        }
        self.prev_keys = current_keys;
    }

    fn handle_key_press(&mut self, scancode: u8) {
        self.update_lock_state(scancode);
        let shift = self.is_shift_active();
        let ascii = hid_to_ascii(scancode, shift);
        let event = KeyEvent { scancode, ascii, pressed: true, modifiers: self.modifiers };
        if self.buffer.len() < KEY_BUFFER_SIZE {
            self.buffer.push_back(event);
        }
    }

    fn handle_key_release(&mut self, scancode: u8) {
        let event = KeyEvent { scancode, ascii: None, pressed: false, modifiers: self.modifiers };
        if self.buffer.len() < KEY_BUFFER_SIZE {
            self.buffer.push_back(event);
        }
    }

    fn update_lock_state(&mut self, scancode: u8) {
        const NUM_LOCK: u8 = 0x53;
        const SCROLL_LOCK: u8 = 0x47;
        match scancode {
            KEY_CAPS_LOCK => {
                self.caps_lock = !self.caps_lock;
                self.update_leds();
            }
            NUM_LOCK => {
                self.num_lock = !self.num_lock;
                self.update_leds();
            }
            SCROLL_LOCK => {
                self.scroll_lock = !self.scroll_lock;
                self.update_leds();
            }
            _ => {}
        }
    }

    fn update_leds(&mut self) {
        self.leds = 0;
        if self.num_lock {
            self.leds |= KEYBOARD_LED_NUM_LOCK;
        }
        if self.caps_lock {
            self.leds |= KEYBOARD_LED_CAPS_LOCK;
        }
        if self.scroll_lock {
            self.leds |= KEYBOARD_LED_SCROLL_LOCK;
        }
    }

    fn is_shift_active(&self) -> bool {
        let shift_held = (self.modifiers & (MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT)) != 0;
        shift_held ^ self.caps_lock
    }

    pub fn pop_event(&mut self) -> Option<KeyEvent> {
        self.buffer.pop_front()
    }

    pub fn get_leds(&self) -> u8 {
        self.leds
    }
}

pub fn process_keyboard_report(report: &[u8; 8]) {
    KEYBOARD.lock().process_report(report);
}

pub fn poll_key() -> Option<KeyEvent> {
    KEYBOARD.lock().pop_event()
}

pub fn get_led_state() -> u8 {
    KEYBOARD.lock().get_leds()
}
