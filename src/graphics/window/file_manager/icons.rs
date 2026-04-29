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

use crate::graphics::framebuffer::fill_rect;

pub fn folder(x: u32, y: u32, color: u32) {
    fill_rect(x, y + 3, 18, 14, color);
    fill_rect(x, y, 8, 4, color);
}

pub fn folder_large(x: u32, y: u32, color: u32) {
    fill_rect(x, y + 8, 48, 32, color);
    fill_rect(x, y, 20, 10, color);
    fill_rect(x + 20, y + 4, 4, 6, color);
    fill_rect(x + 2, y + 12, 44, 2, 0x20FFFFFF);
}

pub fn file(x: u32, y: u32, color: u32) {
    fill_rect(x + 2, y, 12, 18, color);
    fill_rect(x + 2, y, 8, 4, 0xFF48484A);
    fill_rect(x + 10, y + 4, 4, 4, 0xFF48484A);
}

pub fn file_large(x: u32, y: u32, color: u32) {
    fill_rect(x + 4, y, 40, 48, color);
    fill_rect(x + 4, y, 28, 10, 0xFF48484A);
    fill_rect(x + 32, y + 10, 12, 10, 0xFF48484A);
}
