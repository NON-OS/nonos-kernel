// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::fill_rounded_rect;

#[derive(Clone, Copy)]
pub struct TimePicker {
    pub hour: u8,
    pub minute: u8,
    pub is_24h: bool,
}

impl TimePicker {
    pub const fn new(hour: u8, minute: u8) -> Self {
        Self { hour: hour % 24, minute: minute % 60, is_24h: true }
    }

    pub fn set_12h_mode(&mut self) {
        self.is_24h = false;
    }

    pub fn inc_hour(&mut self) {
        self.hour = (self.hour + 1) % 24;
    }

    pub fn dec_hour(&mut self) {
        self.hour = if self.hour == 0 { 23 } else { self.hour - 1 };
    }

    pub fn inc_minute(&mut self) {
        self.minute = (self.minute + 1) % 60;
    }

    pub fn dec_minute(&mut self) {
        self.minute = if self.minute == 0 { 59 } else { self.minute - 1 };
    }

    pub fn draw(&self, x: u32, y: u32) {
        fill_rounded_rect(x, y, 140, 80, 8, BG_ELEVATED);
        draw_text(x + 20, y + 8, b"^", TEXT_PRIMARY);
        draw_text(x + 80, y + 8, b"^", TEXT_PRIMARY);
        let (h_display, is_pm) = if self.is_24h {
            (self.hour, false)
        } else {
            let pm = self.hour >= 12;
            let h = self.hour % 12;
            (if h == 0 { 12 } else { h }, pm)
        };
        let mut time_buf = [0u8; 5];
        time_buf[0] = b'0' + h_display / 10;
        time_buf[1] = b'0' + h_display % 10;
        time_buf[2] = b':';
        time_buf[3] = b'0' + self.minute / 10;
        time_buf[4] = b'0' + self.minute % 10;
        draw_text(x + 30, y + 32, &time_buf, TEXT_PRIMARY);
        draw_text(x + 20, y + 56, b"v", TEXT_PRIMARY);
        draw_text(x + 80, y + 56, b"v", TEXT_PRIMARY);
        if !self.is_24h {
            let ampm = if is_pm { b"PM" } else { b"AM" };
            draw_text(x + 110, y + 32, ampm, TEXT_SECONDARY);
        }
    }

    pub fn handle_click(&mut self, rel_x: u32, rel_y: u32) -> bool {
        if rel_y < 24 {
            if rel_x < 50 {
                self.inc_hour();
                return true;
            }
            if rel_x >= 60 && rel_x < 110 {
                self.inc_minute();
                return true;
            }
        } else if rel_y >= 56 {
            if rel_x < 50 {
                self.dec_hour();
                return true;
            }
            if rel_x >= 60 && rel_x < 110 {
                self.dec_minute();
                return true;
            }
        }
        false
    }
}
