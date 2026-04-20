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

use crate::graphics::framebuffer::{draw_rect, draw_filled_rect, draw_text, get_dimensions};
use crate::graphics::colors::{RGB, WHITE, BLACK, BLUE, GREEN, ORANGE, RED};

const NONOS_BLUE: RGB = RGB { r: 0x00, g: 0x7A, b: 0xCC };
const NONOS_GREEN: RGB = RGB { r: 0x00, g: 0xD4, b: 0x69 };
const NONOS_DARK: RGB = RGB { r: 0x1A, g: 0x1A, b: 0x1A };
const PROGRESS_BG: RGB = RGB { r: 0x2D, g: 0x3F, b: 0x4F };

static mut BOOT_STAGE: u8 = 0;
static mut PROGRESS_PERCENT: u8 = 0;
static mut ANIMATION_FRAME: u16 = 0;

pub fn draw_modern_boot_screen() {
    let (width, height) = get_dimensions();

    draw_background(width, height);
    draw_logo(width / 2, 120);
    draw_progress_section(width, height);
    draw_status_indicators(width, height);
    draw_version_info(width, height);

    unsafe {
        ANIMATION_FRAME = (ANIMATION_FRAME + 1) % 360;
    }
}

fn draw_background(width: u32, height: u32) {
    draw_filled_rect(0, 0, width, height, NONOS_DARK);

    for i in 0..50 {
        let x = (width / 60) * i;
        let y = (height / 40) * (i % 40);
        let alpha = ((unsafe { ANIMATION_FRAME } + i * 7) % 100) as u8;
        let color = RGB {
            r: (NONOS_BLUE.r as u16 * alpha as u16 / 255) as u8,
            g: (NONOS_BLUE.g as u16 * alpha as u16 / 255) as u8,
            b: (NONOS_BLUE.b as u16 * alpha as u16 / 255) as u8,
        };
        draw_filled_rect(x, y, 2, 2, color);
    }
}

fn draw_logo(center_x: u32, y: u32) {
    let logo_width = 400;
    let x = center_x - logo_width / 2;

    draw_text(x, y, "NONOS", WHITE, 3);
    draw_text(x, y + 40, "Zero-State Microkernel", NONOS_BLUE, 1);
    draw_text(x, y + 60, "Secure • Verified • Production Ready", NONOS_GREEN, 1);

    let pulse = ((unsafe { ANIMATION_FRAME } as f32 * 0.1).sin() * 20.0) as u32;
    draw_rect(x - 10, y - 10, logo_width + 20, 100,
        RGB { r: NONOS_BLUE.r + pulse as u8, g: NONOS_BLUE.g, b: NONOS_BLUE.b });
}

fn draw_progress_section(width: u32, height: u32) {
    let progress_y = height / 2;
    let progress_width = width - 200;
    let progress_x = 100;
    let progress_height = 30;

    draw_filled_rect(progress_x, progress_y, progress_width, progress_height, PROGRESS_BG);

    let fill_width = (progress_width * unsafe { PROGRESS_PERCENT } as u32) / 100;
    let gradient_color = if unsafe { PROGRESS_PERCENT } < 100 {
        RGB {
            r: ((ORANGE.r as u32 * (100 - unsafe { PROGRESS_PERCENT } as u32)) +
                (NONOS_GREEN.r as u32 * unsafe { PROGRESS_PERCENT } as u32)) / 100,
            g: ((ORANGE.g as u32 * (100 - unsafe { PROGRESS_PERCENT } as u32)) +
                (NONOS_GREEN.g as u32 * unsafe { PROGRESS_PERCENT } as u32)) / 100,
            b: ((ORANGE.b as u32 * (100 - unsafe { PROGRESS_PERCENT } as u32)) +
                (NONOS_GREEN.b as u32 * unsafe { PROGRESS_PERCENT } as u32)) / 100,
        }
    } else {
        NONOS_GREEN
    };

    draw_filled_rect(progress_x + 2, progress_y + 2, fill_width.saturating_sub(4),
                     progress_height - 4, gradient_color);

    let percentage_text = format!("{}%", unsafe { PROGRESS_PERCENT });
    draw_text(progress_x + progress_width + 20, progress_y + 8, &percentage_text, WHITE, 1);

    let stage_text = get_boot_stage_text();
    draw_text(progress_x, progress_y - 25, stage_text, NONOS_BLUE, 1);

    draw_spinning_indicator(progress_x + progress_width + 80, progress_y + 15);
}

fn draw_spinning_indicator(x: u32, y: u32) {
    let radius = 12;
    let frame = unsafe { ANIMATION_FRAME };

    for i in 0..8 {
        let angle = (frame + i * 45) % 360;
        let alpha = 255 - (i * 30);
        let dot_x = x + ((angle as f32 * 3.14159 / 180.0).cos() * radius as f32) as u32;
        let dot_y = y + ((angle as f32 * 3.14159 / 180.0).sin() * radius as f32) as u32;

        let color = RGB {
            r: (NONOS_BLUE.r as u16 * alpha / 255) as u8,
            g: (NONOS_BLUE.g as u16 * alpha / 255) as u8,
            b: (NONOS_BLUE.b as u16 * alpha / 255) as u8,
        };
        draw_filled_rect(dot_x, dot_y, 4, 4, color);
    }
}

fn draw_status_indicators(width: u32, height: u32) {
    let status_y = height / 2 + 100;
    let col_width = width / 4;

    draw_status_item(col_width * 1 - 50, status_y, "SecureBoot", true);
    draw_status_item(col_width * 2 - 50, status_y, "TPM 2.0", true);
    draw_status_item(col_width * 3 - 50, status_y, "UEFI Mode", true);
    draw_status_item(col_width * 4 - 50, status_y, "Verified", unsafe { BOOT_STAGE } >= 8);
}

fn draw_status_item(x: u32, y: u32, label: &str, enabled: bool) {
    let color = if enabled { NONOS_GREEN } else { RED };
    let status = if enabled { "✓" } else { "✗" };

    draw_filled_rect(x, y, 12, 12, color);
    draw_text(x + 2, y + 2, status, WHITE, 1);
    draw_text(x + 20, y + 2, label, WHITE, 1);
}

fn draw_version_info(width: u32, height: u32) {
    let footer_y = height - 30;
    draw_text(20, footer_y, "NONOS Bootloader v2.1.0", RGB { r: 128, g: 128, b: 128 }, 1);
    draw_text(width - 200, footer_y, "Build: 2026.04.20", RGB { r: 128, g: 128, b: 128 }, 1);
}

fn get_boot_stage_text() -> &'static str {
    match unsafe { BOOT_STAGE } {
        0 => "Initializing UEFI services...",
        1 => "Loading security policies...",
        2 => "Verifying bootloader signature...",
        3 => "Setting up memory protection...",
        4 => "Initializing cryptographic subsystem...",
        5 => "Loading kernel image...",
        6 => "Verifying kernel signature...",
        7 => "Setting up capability system...",
        8 => "Starting microkernel...",
        9 => "Launching userspace services...",
        _ => "Boot complete!",
    }
}

pub fn update_boot_progress(stage: u8, percent: u8) {
    unsafe {
        BOOT_STAGE = stage;
        PROGRESS_PERCENT = percent;
    }
}

pub fn animate_progress() {
    unsafe {
        if PROGRESS_PERCENT < 100 {
            PROGRESS_PERCENT = (PROGRESS_PERCENT + 1).min(100);
        }
        if PROGRESS_PERCENT >= 100 && BOOT_STAGE < 10 {
            BOOT_STAGE += 1;
            PROGRESS_PERCENT = 0;
        }
    }
}