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
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

#[derive(Clone, Copy)]
pub struct Stepper {
    pub value: i32,
    pub min: i32,
    pub max: i32,
    pub step: i32,
    pub width: u32,
}

impl Stepper {
    pub const fn new(value: i32, min: i32, max: i32) -> Self {
        Self { value, min, max, step: 1, width: 120 }
    }

    pub const fn with_step(mut self, step: i32) -> Self {
        self.step = step;
        self
    }

    pub fn increment(&mut self) {
        self.value = (self.value + self.step).min(self.max);
    }

    pub fn decrement(&mut self) {
        self.value = (self.value - self.step).max(self.min);
    }

    pub fn draw(&self, x: u32, y: u32) {
        let btn_w = 32u32;
        let val_w = self.width - btn_w * 2;
        fill_rounded_rect(x, y, btn_w, 32, 6, BG_ELEVATED);
        draw_text(x + 12, y + 10, b"-", TEXT_PRIMARY);
        fill_rect(x + btn_w, y, val_w, 32, BG_INPUT);
        let mut buf = [0u8; 12];
        let len = format_i32(self.value, &mut buf);
        let text_x = x + btn_w + (val_w - len as u32 * 8) / 2;
        draw_text(text_x, y + 10, &buf[..len], TEXT_PRIMARY);
        fill_rounded_rect(x + btn_w + val_w, y, btn_w, 32, 6, BG_ELEVATED);
        draw_text(x + btn_w + val_w + 12, y + 10, b"+", TEXT_PRIMARY);
    }

    pub fn handle_click(&mut self, rel_x: u32) -> bool {
        let btn_w = 32u32;
        let val_w = self.width - btn_w * 2;
        if rel_x < btn_w {
            self.decrement();
            return true;
        }
        if rel_x >= btn_w + val_w {
            self.increment();
            return true;
        }
        false
    }
}

fn format_i32(val: i32, buf: &mut [u8]) -> usize {
    let neg = val < 0;
    let mut v = if neg { (-val) as u32 } else { val as u32 };
    let mut i = buf.len();
    if v == 0 {
        buf[i - 1] = b'0';
        return 1;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if neg && i > 0 {
        i -= 1;
        buf[i] = b'-';
    }
    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    len
}
