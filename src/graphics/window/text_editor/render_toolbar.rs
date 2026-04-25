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

use super::file::is_modified;
use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) fn draw(x: u32, y: u32, w: u32) {
    for gy in 0..TOOLBAR_HEIGHT {
        let shade = 44 - (gy / 2) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + TOOLBAR_HEIGHT - 1, w, 1, BORDER_DEFAULT);

    let tools: [(&[u8], u32); 5] =
        [(b"New", 40), (b"Open", 48), (b"Save", 48), (b"SaveAs", 60), (b"Close", 52)];
    let mut tx = x + 8;
    for (tool, btn_w) in tools.iter() {
        primitives::rounded_rect(tx, y + 6, *btn_w, 26, 6, BG_HOVER);
        text::draw(tx + 8, y + 12, tool, TEXT_PRIMARY);
        tx += btn_w + 6;
    }

    draw_status_indicator(x, y, w);
}

fn draw_status_indicator(x: u32, y: u32, w: u32) {
    let status = EDITOR_STATUS.load(Ordering::Relaxed);
    let modified = is_modified();
    let status_x = x + w - 110;

    match status {
        STATUS_SAVED => {
            primitives::rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A3A1A);
            text::draw(status_x + 24, y + 12, b"Saved", SUCCESS);
        }
        STATUS_OPENED => {
            primitives::rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A2A3A);
            text::draw(status_x + 20, y + 12, b"Opened", ACCENT);
        }
        STATUS_ERROR => {
            primitives::rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF3A1A1A);
            text::draw(status_x + 24, y + 12, b"Error", ERROR);
        }
        STATUS_NEW => {
            primitives::rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A2A3A);
            text::draw(status_x + 32, y + 12, b"New", ACCENT);
        }
        _ => {
            if modified {
                primitives::rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF3A3500);
                text::draw(status_x + 12, y + 12, b"Modified", WARNING);
            }
        }
    }
}
