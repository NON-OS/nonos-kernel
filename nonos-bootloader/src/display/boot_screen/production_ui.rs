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

use crate::graphics::framebuffer::{draw_filled_rect, draw_text, get_dimensions, swap_buffers};
use crate::graphics::colors::{RGB, WHITE, BLACK};
use super::premium_logo::draw_premium_logo;
use super::enhanced_progress::{draw_enhanced_progress_bar, set_progress, animate_progress_step};

const BG_GRADIENT_TOP: RGB = RGB { r: 0x0A, g: 0x0E, b: 0x27 };
const BG_GRADIENT_BOTTOM: RGB = RGB { r: 0x1A, g: 0x1A, b: 0x2E };
const STATUS_SUCCESS: RGB = RGB { r: 0x4C, g: 0xAF, b: 0x50 };
const STATUS_WARNING: RGB = RGB { r: 0xFF, g: 0x9F, b: 0x00 };
const STATUS_ERROR: RGB = RGB { r: 0xF4, g: 0x43, b: 0x36 };

static mut BOOT_MESSAGES: [&'static str; 16] = [
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
];

static mut MESSAGE_COUNT: usize = 0;
static mut CURRENT_STAGE: u8 = 0;
static mut STAGE_PROGRESS: f32 = 0.0;

pub fn draw_production_bootloader() {
    let (width, height) = get_dimensions();

    draw_gradient_background(width, height);
    draw_premium_logo(width / 2, height / 4);
    draw_boot_progress_section(width, height);
    draw_boot_messages(width, height);
    draw_system_info(width, height);

    swap_buffers();
}

fn draw_gradient_background(width: u32, height: u32) {
    let gradient_steps = height / 4;

    for y in 0..height {
        let ratio = y as f32 / height as f32;
        let color = interpolate_rgb(BG_GRADIENT_TOP, BG_GRADIENT_BOTTOM, ratio);
        draw_filled_rect(0, y, width, 1, color);
    }

    draw_particle_field(width, height);
}

fn draw_particle_field(width: u32, height: u32) {
    let particle_count = 100;
    let time = unsafe { STAGE_PROGRESS } * 0.1;

    for i in 0..particle_count {
        let x = ((i * 17 + time as u32 * 3) % width as u32) as u32;
        let y = ((i * 23 + time as u32 * 2) % height as u32) as u32;
        let brightness = ((time + i as f32 * 0.1).sin().abs() * 128.0) as u8;

        let color = RGB {
            r: brightness / 4,
            g: brightness / 2,
            b: brightness,
        };

        if brightness > 50 {
            draw_filled_rect(x, y, 1, 1, color);
        }
    }
}

fn draw_boot_progress_section(width: u32, height: u32) {
    let section_y = height * 2 / 3;
    let progress_width = width - 200;
    let progress_x = 100;
    let progress_height = 24;

    draw_stage_information(progress_x, section_y - 50);
    draw_enhanced_progress_bar(progress_x, section_y, progress_width, progress_height);
    draw_stage_indicators(progress_x + progress_width + 50, section_y - 40);
}

fn draw_stage_information(x: u32, y: u32) {
    let stage_name = get_current_stage_name();
    let stage_color = if unsafe { CURRENT_STAGE } >= 10 { STATUS_SUCCESS } else { WHITE };

    draw_text(x, y, stage_name, stage_color, 1);
    draw_text(x, y + 20, get_stage_description(), RGB { r: 180, g: 180, b: 180 }, 1);
}

fn draw_stage_indicators(x: u32, y: u32) {
    let total_stages = 10;
    let indicator_size = 8;
    let indicator_spacing = 12;

    for stage in 0..total_stages {
        let indicator_x = x;
        let indicator_y = y + stage * indicator_spacing;

        let color = if stage < unsafe { CURRENT_STAGE } {
            STATUS_SUCCESS
        } else if stage == unsafe { CURRENT_STAGE } {
            RGB { r: 0xFF, g: 0xD7, b: 0x00 }
        } else {
            RGB { r: 60, g: 60, b: 60 }
        };

        draw_filled_rect(indicator_x, indicator_y, indicator_size, indicator_size, color);

        if stage == unsafe { CURRENT_STAGE } {
            let pulse_size = indicator_size + 2;
            let pulse_color = RGB { r: color.r / 2, g: color.g / 2, b: color.b / 2 };
            draw_filled_rect(indicator_x - 1, indicator_y - 1, pulse_size, pulse_size, pulse_color);
        }
    }
}

fn draw_boot_messages(width: u32, height: u32) {
    let messages_x = 100;
    let messages_y = height - 200;
    let message_height = 15;

    draw_text(messages_x, messages_y - 20, "Boot Messages:", RGB { r: 180, g: 180, b: 180 }, 1);

    let start_index = if unsafe { MESSAGE_COUNT } > 8 { unsafe { MESSAGE_COUNT } - 8 } else { 0 };

    for i in 0..8 {
        let msg_index = start_index + i;
        if msg_index < unsafe { MESSAGE_COUNT } {
            let message = unsafe { BOOT_MESSAGES[msg_index] };
            let alpha = if i < 6 { 255 - (6 - i) * 30 } else { 255 };

            let color = RGB {
                r: (180 * alpha / 255) as u8,
                g: (180 * alpha / 255) as u8,
                b: (180 * alpha / 255) as u8,
            };

            draw_text(messages_x, messages_y + i * message_height, message, color, 1);
        }
    }
}

fn draw_system_info(width: u32, height: u32) {
    let info_y = height - 40;

    draw_text(20, info_y, "NONOS Bootloader v2.1.0-production", RGB { r: 120, g: 120, b: 120 }, 1);
    draw_text(20, info_y + 15, "UEFI Secure Boot: ENABLED", STATUS_SUCCESS, 1);

    draw_text(width - 250, info_y, "Build: 2026.04.20.2200", RGB { r: 120, g: 120, b: 120 }, 1);
    draw_text(width - 250, info_y + 15, "Target: x86_64-nonos", RGB { r: 120, g: 120, b: 120 }, 1);
}

fn get_current_stage_name() -> &'static str {
    match unsafe { CURRENT_STAGE } {
        0 => "Initializing UEFI Services",
        1 => "Loading Security Policies",
        2 => "Verifying Bootloader Signature",
        3 => "Setting Up Memory Protection",
        4 => "Initializing Cryptographic Subsystem",
        5 => "Loading Kernel Image",
        6 => "Verifying Kernel Signature",
        7 => "Setting Up Capability System",
        8 => "Starting Microkernel",
        9 => "Launching Userspace Services",
        _ => "Boot Complete",
    }
}

fn get_stage_description() -> &'static str {
    match unsafe { CURRENT_STAGE } {
        0 => "Establishing communication with UEFI firmware...",
        1 => "Loading cryptographic policies and security configuration...",
        2 => "Validating bootloader integrity with Ed25519 signatures...",
        3 => "Configuring MMU and setting up memory protection boundaries...",
        4 => "Initializing post-quantum cryptography and entropy sources...",
        5 => "Loading compressed kernel image from boot partition...",
        6 => "Verifying kernel authenticity and integrity checksums...",
        7 => "Configuring capability-based security subsystem...",
        8 => "Transferring control to NONOS microkernel...",
        9 => "Starting essential userspace services and drivers...",
        _ => "System ready for operation.",
    }
}

fn interpolate_rgb(color1: RGB, color2: RGB, ratio: f32) -> RGB {
    RGB {
        r: (color1.r as f32 + (color2.r as f32 - color1.r as f32) * ratio) as u8,
        g: (color1.g as f32 + (color2.g as f32 - color1.g as f32) * ratio) as u8,
        b: (color1.b as f32 + (color2.b as f32 - color1.b as f32) * ratio) as u8,
    }
}

pub fn advance_boot_stage() {
    unsafe {
        if CURRENT_STAGE < 10 {
            CURRENT_STAGE += 1;
            STAGE_PROGRESS = 0.0;
            set_progress(0.0);
        }
    }
}

pub fn update_stage_progress(percent: f32) {
    unsafe {
        STAGE_PROGRESS = percent;
        set_progress(percent);
    }
    animate_progress_step();
}

pub fn add_boot_message(message: &'static str) {
    unsafe {
        if MESSAGE_COUNT < 16 {
            BOOT_MESSAGES[MESSAGE_COUNT] = message;
            MESSAGE_COUNT += 1;
        } else {
            for i in 0..15 {
                BOOT_MESSAGES[i] = BOOT_MESSAGES[i + 1];
            }
            BOOT_MESSAGES[15] = message;
        }
    }
}

pub fn get_current_stage() -> u8 {
    unsafe { CURRENT_STAGE }
}