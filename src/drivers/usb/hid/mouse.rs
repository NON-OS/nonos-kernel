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

use alloc::collections::VecDeque;
use spin::Mutex;

const MOUSE_BUFFER_SIZE: usize = 64;

pub struct MouseState {
    x: i32,
    y: i32,
    buttons: u8,
    prev_buttons: u8,
    buffer: VecDeque<MouseEvent>,
    screen_width: u32,
    screen_height: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    pub x: i32,
    pub y: i32,
    pub dx: i8,
    pub dy: i8,
    pub buttons: u8,
    pub scroll: i8,
    pub event_type: MouseEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEventType {
    Move,
    ButtonDown,
    ButtonUp,
    Scroll,
}

static MOUSE: Mutex<MouseState> = Mutex::new(MouseState::new());

impl MouseState {
    pub const fn new() -> Self {
        Self {
            x: 0,
            y: 0,
            buttons: 0,
            prev_buttons: 0,
            buffer: VecDeque::new(),
            screen_width: 1920,
            screen_height: 1080,
        }
    }

    pub fn set_screen_size(&mut self, width: u32, height: u32) {
        self.screen_width = width;
        self.screen_height = height;
    }

    pub fn process_report(&mut self, report: &[u8]) {
        if report.len() < 3 {
            return;
        }
        let buttons = report[0];
        let dx = report[1] as i8;
        let dy = report[2] as i8;
        let scroll = if report.len() > 3 { report[3] as i8 } else { 0 };
        self.x = (self.x + dx as i32).clamp(0, self.screen_width as i32 - 1);
        self.y = (self.y + dy as i32).clamp(0, self.screen_height as i32 - 1);
        if dx != 0 || dy != 0 {
            self.push_event(MouseEvent {
                x: self.x,
                y: self.y,
                dx,
                dy,
                buttons,
                scroll: 0,
                event_type: MouseEventType::Move,
            });
        }
        self.process_button_changes(buttons);
        if scroll != 0 {
            self.push_event(MouseEvent {
                x: self.x,
                y: self.y,
                dx: 0,
                dy: 0,
                buttons,
                scroll,
                event_type: MouseEventType::Scroll,
            });
        }
        self.prev_buttons = buttons;
        self.buttons = buttons;
    }

    fn process_button_changes(&mut self, new_buttons: u8) {
        let changed = self.prev_buttons ^ new_buttons;
        for bit in 0..8 {
            let mask = 1 << bit;
            if changed & mask != 0 {
                let pressed = new_buttons & mask != 0;
                self.push_event(MouseEvent {
                    x: self.x,
                    y: self.y,
                    dx: 0,
                    dy: 0,
                    buttons: new_buttons,
                    scroll: 0,
                    event_type: if pressed {
                        MouseEventType::ButtonDown
                    } else {
                        MouseEventType::ButtonUp
                    },
                });
            }
        }
    }

    fn push_event(&mut self, event: MouseEvent) {
        if self.buffer.len() < MOUSE_BUFFER_SIZE {
            self.buffer.push_back(event);
        }
    }

    pub fn pop_event(&mut self) -> Option<MouseEvent> {
        self.buffer.pop_front()
    }

    pub fn position(&self) -> (i32, i32) {
        (self.x, self.y)
    }

    pub fn buttons(&self) -> u8 {
        self.buttons
    }
}

pub fn process_mouse_report(report: &[u8]) {
    MOUSE.lock().process_report(report);
}

pub fn poll_mouse() -> Option<MouseEvent> {
    MOUSE.lock().pop_event()
}

pub fn get_position() -> (i32, i32) {
    MOUSE.lock().position()
}

pub fn get_buttons() -> u8 {
    MOUSE.lock().buttons()
}

pub fn set_screen_size(width: u32, height: u32) {
    MOUSE.lock().set_screen_size(width, height);
}
