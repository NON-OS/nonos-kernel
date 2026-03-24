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

use crate::graphics::window::text_editor::SpecialKey;

pub fn draw(x: u32, y: u32, w: u32, h: u32) { super::render::draw(x, y, w, h); }

pub fn handle_click(wx: u32, wy: u32, ww: u32, wh: u32, cx: i32, cy: i32) -> bool {
    super::input::handle_click(wx, wy, ww, wh, cx, cy)
}

pub fn handle_key(ch: u8) { super::input::handle_key(ch); }

pub fn handle_special_key(key: SpecialKey) { super::input::handle_special_key(key); }
