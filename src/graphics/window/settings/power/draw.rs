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

use crate::graphics::framebuffer::{
    fill_rect, COLOR_TEXT_WHITE, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT,
};
use crate::graphics::window::settings::render::draw_string;
use super::state::{BUTTON_WIDTH, BUTTON_HEIGHT};

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    draw_buttons(x, y);
    draw_acpi_states(x, y, w);
    draw_security_info(x, y, w);
}

fn draw_buttons(x: u32, y: u32) {
    draw_string(x + 15, y, b"Power Actions", COLOR_ACCENT);
    let shutdown_x = x + 15;
    let shutdown_y = y + 30;
    fill_rect(shutdown_x, shutdown_y, BUTTON_WIDTH, BUTTON_HEIGHT, COLOR_RED);
    draw_string(shutdown_x + 24, shutdown_y + 10, b"Shutdown", COLOR_TEXT_WHITE);
    let reboot_x = x + 15 + BUTTON_WIDTH + 15;
    let reboot_y = y + 30;
    fill_rect(reboot_x, reboot_y, BUTTON_WIDTH, BUTTON_HEIGHT, 0xFF3D6EE3);
    draw_string(reboot_x + 32, reboot_y + 10, b"Reboot", COLOR_TEXT_WHITE);
}

fn draw_acpi_states(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 85, b"Power States (ACPI)", COLOR_ACCENT);
    let state_x = x + 15;
    let state_y = y + 105;
    fill_rect(state_x, state_y, w - 30, 120, 0xFF1A1F26);
    draw_string(state_x + 10, state_y + 10, b"S0 Working", COLOR_TEXT_WHITE);
    draw_string(state_x + 150, state_y + 10, b"[ACTIVE]", COLOR_GREEN);
    draw_string(state_x + 10, state_y + 30, b"S1 Standby", COLOR_TEXT_WHITE);
    draw_string(state_x + 150, state_y + 30, b"[BLOCKED]", COLOR_RED);
    draw_string(state_x + 230, state_y + 30, b"ZeroState", 0xFF7D8590);
    draw_string(state_x + 10, state_y + 50, b"S3 Suspend", COLOR_TEXT_WHITE);
    draw_string(state_x + 150, state_y + 50, b"[BLOCKED]", COLOR_RED);
    draw_string(state_x + 230, state_y + 50, b"ZeroState", 0xFF7D8590);
    draw_string(state_x + 10, state_y + 70, b"S4 Hibernate", COLOR_TEXT_WHITE);
    draw_string(state_x + 150, state_y + 70, b"[BLOCKED]", COLOR_RED);
    draw_string(state_x + 230, state_y + 70, b"No disk", 0xFF7D8590);
    draw_string(state_x + 10, state_y + 90, b"S5 Soft Off", COLOR_TEXT_WHITE);
    draw_string(state_x + 150, state_y + 90, b"[AVAILABLE]", COLOR_GREEN);
}

fn draw_security_info(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 240, b"ZeroState Security", COLOR_ACCENT);
    let info_x = x + 15;
    let info_y = y + 260;
    fill_rect(info_x, info_y, w - 30, 80, 0xFF1A1F26);
    draw_string(info_x + 10, info_y + 10, b"RAM erased on shutdown", COLOR_GREEN);
    draw_string(info_x + 10, info_y + 30, b"No data persists to disk", COLOR_GREEN);
    draw_string(info_x + 10, info_y + 50, b"Sleep/hibernate disabled", COLOR_YELLOW);
    draw_string(x + 15, y + 355, b"All data will be lost on power action!", COLOR_YELLOW);
}
