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

extern crate alloc;

use crate::graphics::framebuffer::fill_rect;
use alloc::string::{String, ToString};

pub const COLOR_SCROLLBAR: u32 = 0xFF48484A;
pub const COLOR_SCROLLBAR_THUMB: u32 = 0xFF00FFCC;

pub fn draw_scrollbar(x: u32, y: u32, w: u32, h: u32, scroll: usize, total: usize, visible: usize) {
    fill_rect(x, y, w, h, COLOR_SCROLLBAR);
    if total > 0 {
        let thumb_h = ((visible as u32 * h) / total as u32).max(20).min(h);
        let thumb_y = if total > visible {
            y + ((scroll as u32 * (h - thumb_h)) / (total - visible) as u32)
        } else {
            y
        };
        fill_rect(x, thumb_y, w, thumb_h, COLOR_SCROLLBAR_THUMB);
    }
}

pub fn draw_border_thin(x: u32, y: u32, w: u32, h: u32, color: u32) {
    fill_rect(x, y, w, 1, color);
    fill_rect(x, y + h - 1, w, 1, color);
    fill_rect(x, y, 1, h, color);
    fill_rect(x + w - 1, y, 1, h, color);
}

pub fn format_balance(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let gwei = (wei / 1_000_000_000) % 1_000_000_000;
    alloc::format!("{}.{:09}", eth, gwei)
}

pub fn format_status(connected: bool) -> String {
    if connected {
        "Connected".to_string()
    } else {
        "Disconnected".to_string()
    }
}
