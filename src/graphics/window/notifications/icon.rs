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

use super::layout::{icon_position, NotificationLayout, ICON_SIZE};
use super::types::{NOTIFY_ERROR, NOTIFY_INFO, NOTIFY_SUCCESS, NOTIFY_WARNING};
use crate::graphics::components::primitives;
use crate::graphics::design_system::colors::{ACCENT, ERROR, SUCCESS, TEXT_INVERSE, WARNING};
use crate::graphics::font::draw_char;

pub(super) fn draw(layout: &NotificationLayout, ntype: u8) {
    let (ix, iy) = icon_position(layout);
    let color = icon_color(ntype);
    primitives::rounded_rect(ix, iy, ICON_SIZE, ICON_SIZE, 8, color);
    let ch = icon_char(ntype);
    draw_char(ix + 10, iy + 6, ch, TEXT_INVERSE);
}

fn icon_color(ntype: u8) -> u32 {
    match ntype {
        NOTIFY_SUCCESS => SUCCESS,
        NOTIFY_WARNING => WARNING,
        NOTIFY_ERROR => ERROR,
        NOTIFY_INFO | _ => ACCENT,
    }
}

fn icon_char(ntype: u8) -> u8 {
    match ntype {
        NOTIFY_SUCCESS => 0x04,
        NOTIFY_WARNING => b'!',
        NOTIFY_ERROR => b'X',
        NOTIFY_INFO | _ => b'i',
    }
}

pub(super) fn draw_close_button(layout: &NotificationLayout, hover: bool) {
    let (cx, cy) = super::layout::close_position(layout);
    let color = if hover { ERROR } else { 0xFF666680 };
    primitives::rounded_rect(cx, cy, 16, 16, 4, 0x40000000);
    draw_char(cx + 4, cy + 4, b'x', color);
}

pub(super) fn draw_progress_bar(layout: &NotificationLayout, progress: u8) {
    let bar_y = layout.y + layout.height - 3;
    let bar_w = (layout.width - 4) * progress as u32 / 100;
    primitives::rect(layout.x + 2, bar_y, layout.width - 4, 2, 0x20FFFFFF);
    if bar_w > 0 {
        primitives::rect(layout.x + 2, bar_y, bar_w, 2, 0x60FFFFFF);
    }
}
