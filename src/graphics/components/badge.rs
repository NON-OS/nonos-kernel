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

use super::primitives::circle;
use crate::graphics::design_system::colors;
use crate::graphics::framebuffer::rounded_rect_blend;

pub const BADGE_HEIGHT: u32 = 20;
pub const BADGE_MIN_WIDTH: u32 = 20;
pub const BADGE_PADDING: u32 = 6;
pub const DOT_SIZE: u32 = 8;

#[derive(Clone, Copy, PartialEq)]
pub enum BadgeVariant {
    Default,
    Success,
    Warning,
    Error,
    Info,
}

pub fn draw_badge(x: u32, y: u32, text: &[u8], variant: BadgeVariant) {
    let w = (text.len() as u32 * 8 + BADGE_PADDING * 2).max(BADGE_MIN_WIDTH);
    let bg = variant_color(variant);
    rounded_rect_blend(x, y, w, BADGE_HEIGHT, BADGE_HEIGHT / 2, bg);
    let text_x = x + (w - text.len() as u32 * 8) / 2;
    let text_y = y + 2;
    use crate::graphics::font::draw_text;
    draw_text(text_x, text_y, text, colors::TEXT_INVERSE);
}

pub fn draw_badge_count(x: u32, y: u32, count: u32, variant: BadgeVariant) {
    if count == 0 {
        return;
    }
    let text = format_count(count);
    let len = count_len(count);
    draw_badge(x, y, &text[..len], variant);
}

pub fn draw_dot(x: u32, y: u32, variant: BadgeVariant) {
    let color = variant_color(variant);
    let cx = x + DOT_SIZE / 2;
    let cy = y + DOT_SIZE / 2;
    circle(cx, cy, DOT_SIZE / 2, color);
}

pub fn draw_notification_dot(x: u32, y: u32) {
    draw_dot(x, y, BadgeVariant::Error);
}

fn variant_color(variant: BadgeVariant) -> u32 {
    match variant {
        BadgeVariant::Default => colors::ACCENT,
        BadgeVariant::Success => colors::SUCCESS,
        BadgeVariant::Warning => colors::WARNING,
        BadgeVariant::Error => colors::ERROR,
        BadgeVariant::Info => colors::INFO,
    }
}

fn format_count(count: u32) -> [u8; 4] {
    if count > 99 {
        [b'9', b'9', b'+', 0]
    } else if count >= 10 {
        [b'0' + (count / 10) as u8, b'0' + (count % 10) as u8, 0, 0]
    } else {
        [b'0' + count as u8, 0, 0, 0]
    }
}

fn count_len(count: u32) -> usize {
    if count > 99 {
        3
    } else if count >= 10 {
        2
    } else {
        1
    }
}

pub fn badge_width(text_len: usize) -> u32 {
    (text_len as u32 * 8 + BADGE_PADDING * 2).max(BADGE_MIN_WIDTH)
}
