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

use crate::graphics::design_system::{borders, colors};
use crate::graphics::framebuffer::{fill_rect_blend, rounded_rect_blend};

#[derive(Clone, Copy, PartialEq)]
pub enum GlassVariant {
    Default,
    Light,
    Dark,
    Accent,
}

pub fn draw_glass_panel(x: u32, y: u32, w: u32, h: u32, variant: GlassVariant, radius: u32) {
    draw_blur_layers(x, y, w, h, radius);
    let bg = match variant {
        GlassVariant::Default => colors::GLASS_BG,
        GlassVariant::Light => colors::GLASS_BG_LIGHT,
        GlassVariant::Dark => colors::GLASS_BG_DARK,
        GlassVariant::Accent => colors::GLASS_BG,
    };
    rounded_rect_blend(x, y, w, h, radius, bg);
    draw_glass_highlight(x, y, w, radius);
    draw_glass_border(x, y, w, h, radius, variant);
}

pub fn draw_glass(x: u32, y: u32, w: u32, h: u32) {
    draw_glass_panel(x, y, w, h, GlassVariant::Default, borders::RADIUS_LG)
}

pub fn draw_glass_card(x: u32, y: u32, w: u32, h: u32) {
    draw_glass_panel(x, y, w, h, GlassVariant::Default, borders::RADIUS_MD)
}

fn draw_blur_layers(x: u32, y: u32, w: u32, h: u32, radius: u32) {
    rounded_rect_blend(x, y, w, h, radius, colors::BLUR_LAYER_1);
    if radius > 2 {
        rounded_rect_blend(x + 1, y + 1, w - 2, h - 2, radius - 1, colors::BLUR_LAYER_2);
    }
    if radius > 4 {
        rounded_rect_blend(x + 2, y + 2, w - 4, h - 4, radius - 2, colors::BLUR_LAYER_3);
    }
}

fn draw_glass_highlight(x: u32, y: u32, w: u32, radius: u32) {
    if w < 4 {
        return;
    }
    let highlight_w = w - 4;
    fill_rect_blend(x + 2, y + 1, highlight_w, 1, colors::GLASS_HIGHLIGHT);
    fill_rect_blend(x + radius, y + 2, w - radius * 2, 1, colors::FROST_OVERLAY);
}

fn draw_glass_border(x: u32, y: u32, w: u32, h: u32, radius: u32, variant: GlassVariant) {
    let border = match variant {
        GlassVariant::Accent => colors::GLASS_BORDER_ACCENT,
        _ => colors::GLASS_BORDER,
    };
    draw_rounded_border_blend(x, y, w, h, radius, border);
}

fn draw_rounded_border_blend(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    use crate::graphics::framebuffer::put_pixel_blend;
    if w < 2 || h < 2 {
        return;
    }
    for px in (x + r)..(x + w - r) {
        put_pixel_blend(px, y, color);
        put_pixel_blend(px, y + h - 1, color);
    }
    for py in (y + r)..(y + h - r) {
        put_pixel_blend(x, py, color);
        put_pixel_blend(x + w - 1, py, color);
    }
}
