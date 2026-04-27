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
use crate::graphics::design_system::{borders, colors};
use crate::graphics::font::draw_text;

pub const TOOLTIP_PADDING: u32 = 8;
pub const TOOLTIP_HEIGHT: u32 = 28;
pub const TOOLTIP_OFFSET: u32 = 8;
pub const TOOLTIP_DELAY_MS: u64 = 500;

#[derive(Clone, Copy, PartialEq)]
pub enum TooltipPosition {
    Top,
    Bottom,
    Left,
    Right,
}

pub fn draw_tooltip(x: u32, y: u32, text: &[u8], position: TooltipPosition) {
    let w = text.len() as u32 * 8 + TOOLTIP_PADDING * 2;
    let (tx, ty) = calc_position(x, y, w, TOOLTIP_HEIGHT, position);
    draw_glass_panel(tx, ty, w, TOOLTIP_HEIGHT, GlassVariant::Dark, borders::RADIUS_SM);
    draw_text(tx + TOOLTIP_PADDING, ty + 6, text, colors::TEXT_PRIMARY);
}

fn calc_position(x: u32, y: u32, w: u32, h: u32, pos: TooltipPosition) -> (u32, u32) {
    match pos {
        TooltipPosition::Top => (x.saturating_sub(w / 2), y.saturating_sub(h + TOOLTIP_OFFSET)),
        TooltipPosition::Bottom => (x.saturating_sub(w / 2), y + TOOLTIP_OFFSET),
        TooltipPosition::Left => (x.saturating_sub(w + TOOLTIP_OFFSET), y.saturating_sub(h / 2)),
        TooltipPosition::Right => (x + TOOLTIP_OFFSET, y.saturating_sub(h / 2)),
    }
}

pub fn draw_tooltip_at_cursor(mx: u32, my: u32, text: &[u8]) {
    let w = text.len() as u32 * 8 + TOOLTIP_PADDING * 2;
    let tx = mx + 12;
    let ty = my + 16;
    draw_glass_panel(tx, ty, w, TOOLTIP_HEIGHT, GlassVariant::Dark, borders::RADIUS_SM);
    draw_text(tx + TOOLTIP_PADDING, ty + 6, text, colors::TEXT_PRIMARY);
}

#[derive(Clone, Copy, Default)]
pub struct TooltipState {
    pub visible: bool,
    pub hover_start: u64,
    pub x: u32,
    pub y: u32,
}

impl TooltipState {
    pub fn update(&mut self, hovering: bool, x: u32, y: u32, current_time: u64) {
        if hovering {
            if self.x != x || self.y != y {
                self.hover_start = current_time;
                self.visible = false;
            }
            self.x = x;
            self.y = y;
            if current_time - self.hover_start >= TOOLTIP_DELAY_MS {
                self.visible = true;
            }
        } else {
            self.visible = false;
            self.hover_start = current_time;
        }
    }

    pub fn reset(&mut self) {
        self.visible = false;
    }
}

pub fn tooltip_width(text_len: usize) -> u32 {
    text_len as u32 * 8 + TOOLTIP_PADDING * 2
}
