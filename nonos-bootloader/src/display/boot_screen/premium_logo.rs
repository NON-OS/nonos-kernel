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

use crate::graphics::framebuffer::{draw_filled_rect, draw_text, draw_line};
use crate::graphics::colors::{RGB, WHITE, BLACK};

const LOGO_PRIMARY: RGB = RGB { r: 0x00, g: 0xE5, b: 0xFF };
const LOGO_SECONDARY: RGB = RGB { r: 0x00, g: 0x7A, b: 0xCC };
const LOGO_ACCENT: RGB = RGB { r: 0xFF, g: 0x6D, b: 0x00 };
const LOGO_SHADOW: RGB = RGB { r: 0x1A, g: 0x1A, b: 0x2E };

static mut LOGO_ANIMATION: f32 = 0.0;
static mut GLOW_INTENSITY: u8 = 0;

pub fn draw_premium_logo(center_x: u32, center_y: u32) {
    update_logo_animation();

    draw_logo_background(center_x, center_y);
    draw_logo_geometric_elements(center_x, center_y);
    draw_logo_text(center_x, center_y);
    draw_logo_glow_effects(center_x, center_y);
    draw_tagline(center_x, center_y + 80);
}

fn update_logo_animation() {
    unsafe {
        LOGO_ANIMATION += 0.03;
        if LOGO_ANIMATION > 6.28 {
            LOGO_ANIMATION = 0.0;
        }

        GLOW_INTENSITY = (128.0 + 127.0 * LOGO_ANIMATION.sin()) as u8;
    }
}

fn draw_logo_background(center_x: u32, center_y: u32) {
    let bg_size = 200;
    let bg_x = center_x - bg_size / 2;
    let bg_y = center_y - bg_size / 2;

    let gradient_steps = 50;
    for i in 0..gradient_steps {
        let radius = (bg_size * i) / (gradient_steps * 2);
        let alpha = 255 - (i * 5);

        let color = RGB {
            r: (LOGO_SHADOW.r as u16 * alpha / 255) as u8,
            g: (LOGO_SHADOW.g as u16 * alpha / 255) as u8,
            b: (LOGO_SHADOW.b as u16 * alpha / 255) as u8,
        };

        draw_filled_rect(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2,
            color
        );
    }
}

fn draw_logo_geometric_elements(center_x: u32, center_y: u32) {
    let animation = unsafe { LOGO_ANIMATION };

    draw_hexagonal_pattern(center_x, center_y, animation);
    draw_orbital_rings(center_x, center_y, animation);
    draw_central_core(center_x, center_y);
}

fn draw_hexagonal_pattern(center_x: u32, center_y: u32, animation: f32) {
    let hex_radius = 60;
    let hex_count = 6;

    for i in 0..hex_count {
        let angle = (i as f32 * 1.047) + animation * 0.5;
        let x = center_x + (angle.cos() * hex_radius as f32) as u32;
        let y = center_y + (angle.sin() * hex_radius as f32) as u32;

        let size = 8 + (4.0 * (animation + i as f32 * 0.5).sin()) as u32;
        let alpha = (200.0 + 55.0 * (animation * 2.0 + i as f32).sin()) as u8;

        let color = RGB {
            r: (LOGO_PRIMARY.r as u16 * alpha / 255) as u8,
            g: (LOGO_PRIMARY.g as u16 * alpha / 255) as u8,
            b: (LOGO_PRIMARY.b as u16 * alpha / 255) as u8,
        };

        draw_filled_rect(x - size/2, y - size/2, size, size, color);
    }
}

fn draw_orbital_rings(center_x: u32, center_y: u32, animation: f32) {
    let ring_count = 3;
    let base_radius = 30;

    for ring in 0..ring_count {
        let radius = base_radius + (ring * 15);
        let speed = 1.0 + ring as f32 * 0.3;
        let dots_count = 8 + ring * 4;

        for dot in 0..dots_count {
            let angle = (dot as f32 * 6.28 / dots_count as f32) + (animation * speed);
            let x = center_x + (angle.cos() * radius as f32) as u32;
            let y = center_y + (angle.sin() * radius as f32) as u32;

            let intensity = (255.0 * (animation + dot as f32 * 0.2).sin().abs()) as u8;
            let color = match ring {
                0 => RGB { r: (LOGO_ACCENT.r as u16 * intensity / 255) as u8,
                          g: (LOGO_ACCENT.g as u16 * intensity / 255) as u8,
                          b: (LOGO_ACCENT.b as u16 * intensity / 255) as u8 },
                1 => RGB { r: (LOGO_PRIMARY.r as u16 * intensity / 255) as u8,
                          g: (LOGO_PRIMARY.g as u16 * intensity / 255) as u8,
                          b: (LOGO_PRIMARY.b as u16 * intensity / 255) as u8 },
                _ => RGB { r: (LOGO_SECONDARY.r as u16 * intensity / 255) as u8,
                          g: (LOGO_SECONDARY.g as u16 * intensity / 255) as u8,
                          b: (LOGO_SECONDARY.b as u16 * intensity / 255) as u8 },
            };

            let dot_size = 3 + ring;
            draw_filled_rect(x - dot_size/2, y - dot_size/2, dot_size, dot_size, color);
        }
    }
}

fn draw_central_core(center_x: u32, center_y: u32) {
    let core_size = 20;
    let pulse = unsafe { GLOW_INTENSITY };

    let core_color = RGB {
        r: (255 * pulse / 255),
        g: (255 * pulse / 255),
        b: (255 * pulse / 255),
    };

    draw_filled_rect(
        center_x - core_size/2,
        center_y - core_size/2,
        core_size,
        core_size,
        core_color
    );

    let outer_glow_size = core_size + 8;
    let glow_color = RGB {
        r: (LOGO_PRIMARY.r as u16 * pulse / 255) as u8,
        g: (LOGO_PRIMARY.g as u16 * pulse / 255) as u8,
        b: (LOGO_PRIMARY.b as u16 * pulse / 255) as u8,
    };

    draw_filled_rect(
        center_x - outer_glow_size/2,
        center_y - outer_glow_size/2,
        outer_glow_size,
        outer_glow_size,
        glow_color
    );
}

fn draw_logo_text(center_x: u32, center_y: u32) {
    let text_y = center_y + 100;
    let nonos_width = 120;
    let nonos_x = center_x - nonos_width / 2;

    draw_text_with_shadow(nonos_x, text_y, "NONOS", WHITE, LOGO_SHADOW, 4);
}

fn draw_tagline(center_x: u32, center_y: u32) {
    let tagline = "Zero-State Microkernel Operating System";
    let tagline_width = tagline.len() as u32 * 8;
    let tagline_x = center_x - tagline_width / 2;

    draw_text_with_shadow(tagline_x, center_y, tagline, LOGO_SECONDARY, LOGO_SHADOW, 1);

    let subtitle_y = center_y + 25;
    let subtitle = "Secure • Verified • Production Ready";
    let subtitle_width = subtitle.len() as u32 * 6;
    let subtitle_x = center_x - subtitle_width / 2;

    draw_text_with_shadow(subtitle_x, subtitle_y, subtitle, LOGO_ACCENT, LOGO_SHADOW, 1);
}

fn draw_logo_glow_effects(center_x: u32, center_y: u32) {
    let glow_radius = 150;
    let intensity = unsafe { GLOW_INTENSITY };

    for radius in (0..glow_radius).step_by(10) {
        let alpha = ((glow_radius - radius) * intensity as u32 / glow_radius / 3) as u8;
        let color = RGB {
            r: (LOGO_PRIMARY.r as u16 * alpha / 255) as u8,
            g: (LOGO_PRIMARY.g as u16 * alpha / 255) as u8,
            b: (LOGO_PRIMARY.b as u16 * alpha / 255) as u8,
        };

        if alpha > 5 {
            draw_filled_rect(center_x - radius, center_y - 2, radius * 2, 1, color);
            draw_filled_rect(center_x - radius, center_y + 2, radius * 2, 1, color);
            draw_filled_rect(center_x - 2, center_y - radius, 1, radius * 2, color);
            draw_filled_rect(center_x + 2, center_y - radius, 1, radius * 2, color);
        }
    }
}

fn draw_text_with_shadow(x: u32, y: u32, text: &str, color: RGB, shadow_color: RGB, scale: u8) {
    draw_text(x + 2, y + 2, text, shadow_color, scale);
    draw_text(x, y, text, color, scale);
}