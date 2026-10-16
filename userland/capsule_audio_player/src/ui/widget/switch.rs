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

//! Switch and tab bar.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::metrics::{pill, ITEM, S5};
use crate::ui::paint::{disc, fill, panel, rule, shadow, text, width};

use super::slider::accent_dim;

pub const SWITCH_W: i32 = 52;
pub const SWITCH_H: i32 = 28;

pub fn switch(fb: &mut PaintBuffer, r: Rect, on: bool) {
    let (rad, t) = (pill(r.h), roles());
    if on {
        shadow(fb, r, rad, (r.h / 3) as u32, with_alpha(t.accent.argb(), 0x40));
        fill(fb, r, rad, accent_dim());
        fill(fb, Rect::new(r.x, r.y, r.w * 2 / 3, r.h), rad, t.accent.argb());
    } else {
        panel(fb, r, rad, t.sunken.argb(), t.border.argb());
    }
    let k = r.h / 2 - 3;
    let kx = if on { r.right() - k - 3 } else { r.x + k + 3 };
    disc(fb, kx, r.cy(), k, if on { t.on_accent } else { t.text_2 }.argb());
}

pub fn tab_bar(fb: &mut PaintBuffer, r: Rect, tabs: &[&str], selected: usize) {
    let (mut x, t) = (r.x, roles());
    for (i, label) in tabs.iter().enumerate() {
        let w = width(label, ITEM) + S5;
        let active = i == selected;
        let fg = if active { t.text } else { t.text_2 }.argb();
        text(fb, x + S5 / 2, r.cy() - (ITEM * 0.72) as i32, label, fg, ITEM);
        if active {
            fill(fb, Rect::new(x + S5 / 2, r.bottom() - 2, w - S5, 2), 1, t.accent.argb());
        }
        x += w;
    }
    rule(fb, Rect::new(r.x, r.bottom() - 1, r.w, 1));
}

pub fn tab_at(r: Rect, tabs: &[&str], x: i32, y: i32) -> Option<usize> {
    if !r.contains(x, y) {
        return None;
    }
    let mut cx = r.x;
    for (i, label) in tabs.iter().enumerate() {
        let w = width(label, ITEM) + S5;
        if x < cx + w {
            return Some(i);
        }
        cx += w;
    }
    None
}
