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

pub const TOGGLE_WIDTH: u32 = 44;
pub const TOGGLE_HEIGHT: u32 = 24;
pub const THUMB_SIZE: u32 = 18;
pub const THUMB_MARGIN: u32 = 3;

pub fn draw_toggle(x: u32, y: u32, enabled: bool, hovered: bool) {
    let track_color = if enabled { colors::ACCENT } else { colors::GLASS_BG_DARK };
    rounded_rect_blend(x, y, TOGGLE_WIDTH, TOGGLE_HEIGHT, TOGGLE_HEIGHT / 2, track_color);
    if hovered && !enabled {
        rounded_rect_blend(
            x,
            y,
            TOGGLE_WIDTH,
            TOGGLE_HEIGHT,
            TOGGLE_HEIGHT / 2,
            colors::GLASS_HIGHLIGHT,
        );
    }
    let thumb_x =
        if enabled { x + TOGGLE_WIDTH - THUMB_SIZE - THUMB_MARGIN } else { x + THUMB_MARGIN };
    let thumb_y = y + THUMB_MARGIN;
    draw_thumb_knob(thumb_x, thumb_y, enabled);
}

fn draw_thumb_knob(x: u32, y: u32, enabled: bool) {
    let cx = x + THUMB_SIZE / 2;
    let cy = y + THUMB_SIZE / 2;
    let radius = THUMB_SIZE / 2;
    circle(cx, cy, radius, colors::TEXT_PRIMARY);
    if enabled {
        circle(cx, cy, radius - 2, colors::ACCENT_GLOW);
    }
}

pub fn toggle_hit_test(x: u32, y: u32, click_x: i32, click_y: i32) -> bool {
    click_x >= x as i32
        && click_x < (x + TOGGLE_WIDTH) as i32
        && click_y >= y as i32
        && click_y < (y + TOGGLE_HEIGHT) as i32
}

pub fn draw_toggle_with_label(x: u32, y: u32, label: &[u8], enabled: bool, hovered: bool) {
    use crate::graphics::font::draw_text;
    draw_text(x, y + 4, label, colors::TEXT_PRIMARY);
    draw_toggle(x + label.len() as u32 * 8 + 16, y, enabled, hovered);
}

pub fn draw_toggle_row(x: u32, y: u32, w: u32, label: &[u8], enabled: bool, hovered: bool) {
    use crate::graphics::font::draw_text;
    draw_text(x, y + 4, label, colors::TEXT_PRIMARY);
    let toggle_x = x + w - TOGGLE_WIDTH;
    draw_toggle(toggle_x, y, enabled, hovered);
}

pub fn toggle_row_hit_test(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    let toggle_x = x + w - TOGGLE_WIDTH;
    toggle_hit_test(toggle_x, y, click_x, click_y)
}

#[derive(Clone, Copy, PartialEq)]
pub enum ToggleSize {
    Small,
    Medium,
    Large,
}

pub fn toggle_dimensions(size: ToggleSize) -> (u32, u32) {
    match size {
        ToggleSize::Small => (36, 20),
        ToggleSize::Medium => (44, 24),
        ToggleSize::Large => (52, 28),
    }
}
