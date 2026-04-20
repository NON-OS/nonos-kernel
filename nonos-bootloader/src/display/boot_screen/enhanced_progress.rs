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

use crate::graphics::framebuffer::{draw_filled_rect, draw_text, get_dimensions};
use crate::graphics::colors::{RGB, WHITE, BLACK};

const PROGRESS_PRIMARY: RGB = RGB { r: 0x00, g: 0xBC, b: 0xD4 };
const PROGRESS_SECONDARY: RGB = RGB { r: 0xFF, g: 0x6B, b: 0x35 };
const PROGRESS_SUCCESS: RGB = RGB { r: 0x4C, g: 0xAF, b: 0x50 };
const PROGRESS_BG_DARK: RGB = RGB { r: 0x37, g: 0x47, b: 0x4F };

static mut CURRENT_PROGRESS: f32 = 0.0;
static mut TARGET_PROGRESS: f32 = 0.0;
static mut SMOOTH_ANIMATION: f32 = 0.0;
static mut PULSE_TIMER: u16 = 0;

pub fn draw_enhanced_progress_bar(x: u32, y: u32, width: u32, height: u32) {
    update_smooth_progress();

    draw_progress_background(x, y, width, height);
    draw_progress_fill(x, y, width, height);
    draw_progress_glow(x, y, width, height);
    draw_progress_text(x, y, width, height);
}

fn update_smooth_progress() {
    unsafe {
        let target = TARGET_PROGRESS;
        let current = CURRENT_PROGRESS;

        if (target - current).abs() > 0.1 {
            CURRENT_PROGRESS += (target - current) * 0.08;
        } else {
            CURRENT_PROGRESS = target;
        }

        SMOOTH_ANIMATION += 0.05;
        if SMOOTH_ANIMATION > 6.28 {
            SMOOTH_ANIMATION = 0.0;
        }

        PULSE_TIMER = (PULSE_TIMER + 1) % 100;
    }
}

fn draw_progress_background(x: u32, y: u32, width: u32, height: u32) {
    draw_filled_rect(x, y, width, height, PROGRESS_BG_DARK);

    let border_color = RGB { r: 0x54, g: 0x6E, b: 0x7A };
    draw_filled_rect(x, y, width, 2, border_color);
    draw_filled_rect(x, y + height - 2, width, 2, border_color);
    draw_filled_rect(x, y, 2, height, border_color);
    draw_filled_rect(x + width - 2, y, 2, height, border_color);
}

fn draw_progress_fill(x: u32, y: u32, width: u32, height: u32) {
    let progress = unsafe { CURRENT_PROGRESS };
    let fill_width = ((width - 4) as f32 * progress / 100.0) as u32;

    if fill_width > 0 {
        let gradient_steps = fill_width.min(50);

        for i in 0..gradient_steps {
            let ratio = i as f32 / gradient_steps as f32;
            let color = interpolate_color(PROGRESS_PRIMARY, PROGRESS_SUCCESS, ratio);

            let segment_width = if i == gradient_steps - 1 {
                fill_width - i
            } else {
                fill_width / gradient_steps
            };

            draw_filled_rect(x + 2 + i, y + 2, segment_width, height - 4, color);
        }

        draw_shimmer_effect(x + 2, y + 2, fill_width, height - 4);
    }
}

fn draw_shimmer_effect(x: u32, y: u32, width: u32, height: u32) {
    let animation = unsafe { SMOOTH_ANIMATION };
    let shimmer_pos = ((animation.sin() + 1.0) * 0.5 * width as f32) as u32;
    let shimmer_width = 20;

    if shimmer_pos > 0 && shimmer_pos < width {
        let shimmer_color = RGB { r: 255, g: 255, b: 255 };
        let shimmer_actual_width = shimmer_width.min(width - shimmer_pos);

        for i in 0..shimmer_actual_width {
            let alpha = (255 * (shimmer_width - i) / shimmer_width) as u8;
            let color = RGB {
                r: (shimmer_color.r as u16 * alpha as u16 / 255) as u8,
                g: (shimmer_color.g as u16 * alpha as u16 / 255) as u8,
                b: (shimmer_color.b as u16 * alpha as u16 / 255) as u8,
            };
            draw_filled_rect(x + shimmer_pos + i, y, 1, height, color);
        }
    }
}

fn draw_progress_glow(x: u32, y: u32, width: u32, height: u32) {
    let progress = unsafe { CURRENT_PROGRESS };
    let pulse = unsafe { PULSE_TIMER };

    if progress > 0.0 {
        let glow_intensity = (50.0 + 30.0 * (pulse as f32 * 0.1).sin()) as u8;
        let glow_color = RGB {
            r: (PROGRESS_PRIMARY.r as u16 * glow_intensity / 255) as u8,
            g: (PROGRESS_PRIMARY.g as u16 * glow_intensity / 255) as u8,
            b: (PROGRESS_PRIMARY.b as u16 * glow_intensity / 255) as u8,
        };

        draw_filled_rect(x, y - 2, width, 1, glow_color);
        draw_filled_rect(x, y + height + 1, width, 1, glow_color);
    }
}

fn draw_progress_text(x: u32, y: u32, width: u32, _height: u32) {
    let progress = unsafe { CURRENT_PROGRESS };
    let percentage_text = format!("{:.1}%", progress);

    draw_text(x + width + 15, y + 8, &percentage_text, WHITE, 1);

    if progress >= 100.0 {
        draw_text(x, y - 25, "✓ Complete", PROGRESS_SUCCESS, 1);
    } else {
        let dots_count = (unsafe { PULSE_TIMER } / 10) % 4;
        let loading_text = match dots_count {
            0 => "Loading",
            1 => "Loading.",
            2 => "Loading..",
            _ => "Loading...",
        };
        draw_text(x, y - 25, loading_text, PROGRESS_PRIMARY, 1);
    }
}

fn interpolate_color(color1: RGB, color2: RGB, ratio: f32) -> RGB {
    RGB {
        r: (color1.r as f32 + (color2.r as f32 - color1.r as f32) * ratio) as u8,
        g: (color1.g as f32 + (color2.g as f32 - color1.g as f32) * ratio) as u8,
        b: (color1.b as f32 + (color2.b as f32 - color1.b as f32) * ratio) as u8,
    }
}

pub fn set_progress(percentage: f32) {
    unsafe {
        TARGET_PROGRESS = percentage.max(0.0).min(100.0);
    }
}

pub fn get_current_progress() -> f32 {
    unsafe { CURRENT_PROGRESS }
}

pub fn animate_progress_step() {
    unsafe {
        if TARGET_PROGRESS < 100.0 {
            TARGET_PROGRESS += 0.5;
        }
    }
}