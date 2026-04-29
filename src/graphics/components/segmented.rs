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

pub struct SegmentedControl<'a> {
    pub segments: &'a [&'a [u8]],
    pub selected: usize,
    pub width: u32,
    pub height: u32,
}

impl<'a> SegmentedControl<'a> {
    pub const fn new(segments: &'a [&'a [u8]]) -> Self {
        Self { segments, selected: 0, width: 0, height: 32 }
    }

    pub fn with_width(mut self, w: u32) -> Self {
        self.width = w;
        self
    }

    pub fn segment_width(&self) -> u32 {
        if self.width > 0 {
            self.width / self.segments.len() as u32
        } else {
            let max_len = self.segments.iter().map(|s| s.len()).max().unwrap_or(4);
            (max_len as u32 * 8 + 24).max(60)
        }
    }

    pub fn total_width(&self) -> u32 {
        self.segment_width() * self.segments.len() as u32
    }

    pub fn draw(&self, x: u32, y: u32) {
        let seg_w = self.segment_width();
        let total_w = self.total_width();
        fill_rounded_rect(x, y, total_w, self.height, 6, BG_INPUT);
        for (i, label) in self.segments.iter().enumerate() {
            let sx = x + i as u32 * seg_w;
            if i == self.selected {
                fill_rounded_rect(sx + 2, y + 2, seg_w - 4, self.height - 4, 4, ACCENT);
            }
            let text_color = if i == self.selected { 0xFF0C0C10 } else { TEXT_PRIMARY };
            let text_x = sx + (seg_w - label.len() as u32 * 8) / 2;
            let text_y = y + (self.height - 16) / 2;
            draw_text(text_x, text_y, label, text_color);
            if i > 0 && i != self.selected && i - 1 != self.selected {
                fill_rect(sx, y + 6, 1, self.height - 12, BORDER_SUBTLE);
            }
        }
    }

    pub fn handle_click(&mut self, rel_x: u32) -> bool {
        let seg_w = self.segment_width();
        let idx = (rel_x / seg_w) as usize;
        if idx < self.segments.len() && idx != self.selected {
            self.selected = idx;
            return true;
        }
        false
    }
}
