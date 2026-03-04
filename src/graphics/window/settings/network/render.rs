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

use crate::drivers::wifi as wifi_driver;
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE};
use crate::graphics::window::settings::render::draw_string;

use super::ethernet;
use super::wifi;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    let mut cy = y;

    if wifi_driver::is_available() {
        wifi::draw(x, cy, w);
        cy += 280;
    } else {
        draw_string(x + 15, cy, b"WiFi", COLOR_TEXT_WHITE);
        cy += 25;
        fill_rect(x + 15, cy, w - 30, 60, 0xFF1A1F26);
        draw_string(x + 25, cy + 10, b"No WiFi adapter detected", 0xFF7D8590);
        draw_string(x + 25, cy + 30, b"Connect WiFi hardware to scan networks", 0xFF5D6570);
        cy += 80;
    }

    fill_rect(x + 15, cy, w - 30, 1, 0xFF2D333B);
    cy += 15;

    ethernet::draw(x, cy, w);
}
