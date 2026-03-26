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

use crate::graphics::framebuffer::fill_rect;
use crate::graphics::design_system::colors::*;

pub fn folder(x: u32, y: u32, color: u32) {
    fill_rect(x, y + 3, 18, 14, color);
    fill_rect(x, y, 8, 4, color);
}

pub fn file(x: u32, y: u32, color: u32) {
    fill_rect(x + 2, y, 12, 18, color);
    fill_rect(x + 2, y, 8, 4, BG_HOVER);
    fill_rect(x + 10, y + 4, 4, 4, BG_HOVER);
}
