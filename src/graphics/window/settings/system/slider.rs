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

use crate::display::framebuffer::{COLOR_ACCENT};
use crate::graphics::framebuffer::{fill_rect};

pub(super) fn draw_slider(x: u32, y: u32, w: u32, value: u8, max: u8) {
    fill_rect(x, y + 8, w, 8, 0xFF374151);
    let fill_w = ((value as u32) * w) / (max as u32);
    fill_rect(x, y + 8, fill_w, 8, COLOR_ACCENT);
    let knob_x = x + fill_w;
    fill_rect(knob_x.saturating_sub(6), y + 4, 12, 16, 0xFFFFFFFF);
}
