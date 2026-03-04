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
use super::render::draw_string;
use core::sync::atomic::{AtomicBool, Ordering};

static POWER_ACTION_REBOOT: AtomicBool = AtomicBool::new(false);
static POWER_ACTION_SHUTDOWN: AtomicBool = AtomicBool::new(false);

const BUTTON_WIDTH: u32 = 120;
const BUTTON_HEIGHT: u32 = 32;

pub(super) fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"Power Actions", COLOR_ACCENT);

    let shutdown_x = x + 15;
    let shutdown_y = y + 30;
    fill_rect(shutdown_x, shutdown_y, BUTTON_WIDTH, BUTTON_HEIGHT, COLOR_RED);
    draw_string(shutdown_x + 24, shutdown_y + 10, b"Shutdown", COLOR_TEXT_WHITE);

    let reboot_x = x + 15 + BUTTON_WIDTH + 15;
    let reboot_y = y + 30;
    fill_rect(reboot_x, reboot_y, BUTTON_WIDTH, BUTTON_HEIGHT, 0xFF3D6EE3);
    draw_string(reboot_x + 32, reboot_y + 10, b"Reboot", COLOR_TEXT_WHITE);

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

    draw_string(x + 15, y + 240, b"ZeroState Security", COLOR_ACCENT);

    let info_x = x + 15;
    let info_y = y + 260;
    fill_rect(info_x, info_y, w - 30, 80, 0xFF1A1F26);

    draw_string(info_x + 10, info_y + 10, b"RAM erased on shutdown", COLOR_GREEN);
    draw_string(info_x + 10, info_y + 30, b"No data persists to disk", COLOR_GREEN);
    draw_string(info_x + 10, info_y + 50, b"Sleep/hibernate disabled", COLOR_YELLOW);

    draw_string(x + 15, y + 355, b"All data will be lost on power action!", COLOR_YELLOW);
}

pub(super) fn handle_click(content_x: u32, content_y: u32, _content_w: u32, click_x: i32, click_y: i32) -> bool {
    let shutdown_x = content_x + 15;
    let shutdown_y = content_y + 75;
    if click_x >= shutdown_x as i32 && click_x < (shutdown_x + BUTTON_WIDTH) as i32 {
        if click_y >= shutdown_y as i32 && click_y < (shutdown_y + BUTTON_HEIGHT) as i32 {
            POWER_ACTION_SHUTDOWN.store(true, Ordering::Relaxed);
            return true;
        }
    }

    let reboot_x = content_x + 15 + BUTTON_WIDTH + 15;
    let reboot_y = content_y + 75;
    if click_x >= reboot_x as i32 && click_x < (reboot_x + BUTTON_WIDTH) as i32 {
        if click_y >= reboot_y as i32 && click_y < (reboot_y + BUTTON_HEIGHT) as i32 {
            POWER_ACTION_REBOOT.store(true, Ordering::Relaxed);
            return true;
        }
    }

    false
}

pub fn take_reboot_action() -> bool {
    POWER_ACTION_REBOOT.swap(false, Ordering::Relaxed)
}

pub fn take_shutdown_action() -> bool {
    POWER_ACTION_SHUTDOWN.swap(false, Ordering::Relaxed)
}

pub fn process_power_actions() {
    if take_reboot_action() {
        crate::shell::commands::power::cmd_reboot();
    }
    if take_shutdown_action() {
        crate::shell::commands::power::cmd_shutdown();
    }
}
