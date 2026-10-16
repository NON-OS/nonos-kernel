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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Rect as Area, Separator};

use crate::ui::fit::width;
use crate::ui::layout::Rect;
use crate::ui::text::{center_y, BODY_PX};

pub const TABS_H: u32 = 42;
const PAD: u32 = 16;
const RULE: u32 = 3;

pub fn tab_rect(x: u32, y: u32, labels: &[&str], index: usize) -> Rect {
    let mut pen = x;
    for label in labels.iter().take(index) {
        pen += width(label, BODY_PX) + PAD * 2;
    }
    let w = labels.get(index).map(|l| width(l, BODY_PX) + PAD * 2).unwrap_or(0);
    Rect { x: pen, y, w, h: TABS_H }
}

pub fn tab_hit(x: u32, y: u32, labels: &[&str], px: i32, py: i32) -> Option<usize> {
    (0..labels.len()).find(|&i| tab_rect(x, y, labels, i).contains(px, py))
}

pub fn paint_tabs(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, labels: &[&str], active: usize) {
    let theme = roles();
    Separator::new().draw(fb, Area { x, y: y + TABS_H, w, h: 1 });
    for (i, label) in labels.iter().enumerate() {
        let r = tab_rect(x, y, labels, i);
        let ink = if i == active { theme.text } else { theme.muted }.argb();
        fb.text_ttf((r.x + PAD) as i32, center_y(r.y, TABS_H), label, ink, BODY_PX);
        if i == active {
            fb.fill_rect(r.x, y + TABS_H + 1 - RULE, r.w, RULE, theme.accent.argb());
        }
    }
}
