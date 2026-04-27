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

use super::brand;
use crate::graphics::{font, framebuffer};

pub(super) fn clear() {
    framebuffer::clear(brand::BG_PRIMARY);
}
pub(super) fn text(s: &str, x: i32, y: i32, c: u32) {
    font::draw_text(x as u32, y as u32, s.as_bytes(), c);
}
pub(super) fn rect(x: u32, y: u32, w: u32, h: u32, c: u32) {
    framebuffer::fill_rect(x, y, w, h, c);
}

pub(super) fn text_centered(s: &str, y: i32, c: u32) {
    let (w, _) = framebuffer::dimensions();
    text(s, ((w - s.len() as u32 * 8) / 2) as i32, y, c);
}

pub(super) fn logo(y: u32) {
    let (w, _) = framebuffer::dimensions();
    let x = (w - brand::LOGO[0].len() as u32 * 8) / 2;
    for (i, l) in brand::LOGO.iter().enumerate() {
        text(l, x as i32, (y + i as u32 * 16) as i32, brand::ACCENT_PRIMARY);
    }
}

pub(super) fn menu_item(x: u32, y: u32, w: u32, label: &str, sel: bool) {
    let (bg, fg) = if sel {
        (brand::BG_CARD, brand::ACCENT_PRIMARY)
    } else {
        (brand::BG_PRIMARY, brand::TEXT_PRIMARY)
    };
    rect(x, y, w, 35, bg);
    if sel {
        rect(x, y, 3, 35, brand::ACCENT_PRIMARY);
    }
    text(label, (x + 16) as i32, (y + 10) as i32, fg);
}

pub(super) fn checkbox(x: u32, y: u32, label: &str, checked: bool, sel: bool) {
    let fg = if sel { brand::ACCENT_PRIMARY } else { brand::TEXT_PRIMARY };
    text(if checked { "[X]" } else { "[ ]" }, x as i32, y as i32, fg);
    text(label, (x + 32) as i32, y as i32, fg);
}

pub(super) fn progress_dots(y: u32, cur: usize, total: usize) {
    let (w, _) = framebuffer::dimensions();
    let sx = (w - total as u32 * 20) / 2;
    for i in 0..total {
        let c = if i == cur {
            brand::ACCENT_PRIMARY
        } else if i < cur {
            brand::ACCENT_SECONDARY
        } else {
            brand::BORDER
        };
        rect(sx + i as u32 * 20, y, 10, 10, c);
    }
}

pub(super) fn footer(left: &str, right: &str) {
    let (w, h) = framebuffer::dimensions();
    rect(0, h - 50, w, 50, brand::BG_SECONDARY);
    text(left, 20, (h - 35) as i32, brand::TEXT_MUTED);
    text(right, (w - right.len() as u32 * 8 - 20) as i32, (h - 35) as i32, brand::TEXT_MUTED);
}
