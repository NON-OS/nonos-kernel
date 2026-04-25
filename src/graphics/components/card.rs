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

use super::glass_panel::{draw_glass_panel, GlassVariant};
use super::primitives::{rounded_rect, shadow};
use crate::graphics::design_system::{colors, shadows};
use crate::graphics::framebuffer::rounded_rect_blend;

pub const CARD_PADDING: u32 = 16;
pub const CARD_RADIUS: u32 = 12;

#[derive(Clone, Copy, PartialEq)]
pub enum CardVariant {
    Default,
    Elevated,
    Glass,
    Interactive,
}

pub fn draw_card(x: u32, y: u32, w: u32, h: u32, variant: CardVariant, hovered: bool) {
    match variant {
        CardVariant::Default => draw_default_card(x, y, w, h),
        CardVariant::Elevated => draw_elevated_card(x, y, w, h),
        CardVariant::Glass => draw_glass_card(x, y, w, h, hovered),
        CardVariant::Interactive => draw_interactive_card(x, y, w, h, hovered),
    }
}

fn draw_default_card(x: u32, y: u32, w: u32, h: u32) {
    rounded_rect(x, y, w, h, CARD_RADIUS, colors::BG_CARD);
}

fn draw_elevated_card(x: u32, y: u32, w: u32, h: u32) {
    shadow(x, y, w, h, CARD_RADIUS, &shadows::SHADOW_MD);
    rounded_rect(x, y, w, h, CARD_RADIUS, colors::BG_CARD);
}

fn draw_glass_card(x: u32, y: u32, w: u32, h: u32, hovered: bool) {
    let variant = if hovered { GlassVariant::Light } else { GlassVariant::Default };
    draw_glass_panel(x, y, w, h, variant, CARD_RADIUS);
}

fn draw_interactive_card(x: u32, y: u32, w: u32, h: u32, hovered: bool) {
    if hovered {
        shadow(x, y, w, h, CARD_RADIUS, &shadows::SHADOW_LG);
        rounded_rect(x, y, w, h, CARD_RADIUS, colors::BG_CARD_HOVER);
        rounded_rect_blend(x, y, w, h, CARD_RADIUS, colors::GLASS_GLOW_ACCENT);
    } else {
        shadow(x, y, w, h, CARD_RADIUS, &shadows::SHADOW_SM);
        rounded_rect(x, y, w, h, CARD_RADIUS, colors::BG_CARD);
    }
}

pub fn card_content_area(x: u32, y: u32, w: u32, h: u32) -> (u32, u32, u32, u32) {
    (x + CARD_PADDING, y + CARD_PADDING, w - CARD_PADDING * 2, h - CARD_PADDING * 2)
}

pub fn card_hit_test(x: u32, y: u32, w: u32, h: u32, click_x: i32, click_y: i32) -> bool {
    click_x >= x as i32
        && click_x < (x + w) as i32
        && click_y >= y as i32
        && click_y < (y + h) as i32
}

pub fn draw_card_header(x: u32, y: u32, _w: u32, title: &[u8]) {
    use crate::graphics::font::draw_text;
    draw_text(x + CARD_PADDING, y + CARD_PADDING, title, colors::TEXT_PRIMARY);
}

pub fn draw_card_divider(x: u32, y: u32, w: u32) {
    use crate::graphics::framebuffer::fill_rect;
    fill_rect(x + CARD_PADDING, y, w - CARD_PADDING * 2, 1, colors::BORDER_DEFAULT);
}
