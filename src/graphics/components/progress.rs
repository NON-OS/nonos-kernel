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

use crate::graphics::design_system::colors;
use crate::graphics::framebuffer::{fill_rect, rounded_rect_blend};

pub const PROGRESS_HEIGHT: u32 = 8;
pub const PROGRESS_HEIGHT_THICK: u32 = 12;

#[derive(Clone, Copy, PartialEq)]
pub enum ProgressVariant {
    Default,
    Success,
    Warning,
    Error,
}

pub fn draw_progress(x: u32, y: u32, w: u32, value: f32, variant: ProgressVariant) {
    draw_progress_bar(x, y, w, PROGRESS_HEIGHT, value, variant)
}

pub fn draw_progress_bar(x: u32, y: u32, w: u32, h: u32, value: f32, variant: ProgressVariant) {
    let radius = h / 2;
    rounded_rect_blend(x, y, w, h, radius, colors::GLASS_BG_DARK);
    let clamped = value.clamp(0.0, 1.0);
    let fill_w = ((w as f32 * clamped) as u32).max(if clamped > 0.0 { h } else { 0 });
    if fill_w > 0 {
        let fill_color = match variant {
            ProgressVariant::Default => colors::ACCENT,
            ProgressVariant::Success => colors::SUCCESS,
            ProgressVariant::Warning => colors::WARNING,
            ProgressVariant::Error => colors::ERROR,
        };
        rounded_rect_blend(x, y, fill_w, h, radius, fill_color);
    }
}

pub fn draw_progress_with_label(
    x: u32,
    y: u32,
    w: u32,
    value: f32,
    label: &[u8],
    variant: ProgressVariant,
) {
    use crate::graphics::font::draw_text;
    draw_text(x, y, label, colors::TEXT_PRIMARY);
    let pct = format_percent(value);
    let pct_x = x + w - pct.len() as u32 * 8;
    draw_text(pct_x, y, &pct, colors::TEXT_SECONDARY);
    draw_progress(x, y + 20, w, value, variant);
}

fn format_percent(v: f32) -> [u8; 4] {
    let pct = (v * 100.0).min(100.0) as u32;
    let d0 = b'0' + (pct / 100) as u8;
    let d1 = b'0' + ((pct / 10) % 10) as u8;
    let d2 = b'0' + (pct % 10) as u8;
    if pct >= 100 {
        [d0, d1, d2, b'%']
    } else if pct >= 10 {
        [b' ', d1, d2, b'%']
    } else {
        [b' ', b' ', d2, b'%']
    }
}

pub fn draw_indeterminate(x: u32, y: u32, w: u32, offset: u32) {
    let radius = PROGRESS_HEIGHT / 2;
    rounded_rect_blend(x, y, w, PROGRESS_HEIGHT, radius, colors::GLASS_BG_DARK);
    let bar_w = w / 4;
    let bar_x = x + (offset % (w - bar_w));
    rounded_rect_blend(bar_x, y, bar_w, PROGRESS_HEIGHT, radius, colors::ACCENT);
}

pub fn draw_circular(cx: u32, cy: u32, radius: u32, value: f32, thickness: u32) {
    use super::primitives::circle;
    circle(cx, cy, radius, colors::GLASS_BG_DARK);
    if radius > thickness {
        circle(cx, cy, radius - thickness, colors::BG_APP);
    }
    draw_arc_fill(cx, cy, radius, thickness, value);
}

fn draw_arc_fill(cx: u32, cy: u32, radius: u32, thickness: u32, value: f32) {
    let segments = (value.clamp(0.0, 1.0) * 360.0) as i32;
    for angle in 0..segments {
        let rad = (angle as f32 - 90.0) * core::f32::consts::PI / 180.0;
        let outer_r = radius as f32;
        let px = cx as f32 + outer_r * libm::cosf(rad);
        let py = cy as f32 + outer_r * libm::sinf(rad);
        fill_rect(px as u32, py as u32, thickness, thickness, colors::ACCENT);
    }
}
