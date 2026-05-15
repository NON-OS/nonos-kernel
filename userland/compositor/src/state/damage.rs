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

// Damage accumulates into a single screen-aligned bounding rectangle
// for v1. Per-tile damage queues land alongside multi-CPU render
// workers in a follow-up. A `pending` flag distinguishes "no damage"
// from "fully damaged" (initial frame) without sentinel rects.

#[derive(Clone, Copy, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

pub struct DamageAccumulator {
    bbox: Rect,
    pending: bool,
}

impl DamageAccumulator {
    pub const fn new() -> Self {
        Self { bbox: Rect { x: 0, y: 0, width: 0, height: 0 }, pending: false }
    }

    pub fn mark_full(&mut self, width: u32, height: u32) {
        self.bbox = Rect { x: 0, y: 0, width, height };
        self.pending = true;
    }

    pub fn accumulate(&mut self, r: Rect) {
        if r.width == 0 || r.height == 0 {
            return;
        }
        if !self.pending {
            self.bbox = r;
            self.pending = true;
            return;
        }
        let x0 = core::cmp::min(self.bbox.x, r.x);
        let y0 = core::cmp::min(self.bbox.y, r.y);
        let x1 = core::cmp::max(self.bbox.x + self.bbox.width, r.x + r.width);
        let y1 = core::cmp::max(self.bbox.y + self.bbox.height, r.y + r.height);
        self.bbox = Rect { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
    }

    pub fn drain(&mut self) -> Option<Rect> {
        if !self.pending {
            return None;
        }
        let r = self.bbox;
        self.pending = false;
        Some(r)
    }
}
