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

pub fn draw_marketplace(x: u32, y: u32, w: u32, h: u32) {
    super::marketplace::draw(x, y, w, h);
}

pub fn handle_marketplace_click(x: u32, y: u32, w: u32, h: u32, mx: i32, my: i32) -> bool {
    super::marketplace::handle_click(x, y, w, h, mx, my)
}

pub fn marketplace_key(ch: u8) {
    super::marketplace::handle_key(ch);
}

pub fn draw_developer(x: u32, y: u32, w: u32, h: u32) {
    super::developer::draw(x, y, w, h);
}

pub fn handle_developer_click(x: u32, y: u32, w: u32, h: u32, mx: i32, my: i32) -> bool {
    super::developer::handle_click(x, y, w, h, mx, my)
}

pub fn developer_key(ch: u8) {
    super::developer::handle_key(ch);
}

pub fn draw_agents(x: u32, y: u32, w: u32, h: u32) {
    super::agents::draw(x, y, w, h);
}

pub fn handle_agents_click(x: u32, y: u32, w: u32, h: u32, mx: i32, my: i32) -> bool {
    super::agents::handle_click(x, y, w, h, mx, my)
}

pub fn agents_key(ch: u8) {
    super::agents::handle_key(ch);
}
