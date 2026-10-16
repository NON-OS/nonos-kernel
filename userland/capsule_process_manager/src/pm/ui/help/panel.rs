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

//! The overlay itself.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Card, Rect};

use super::super::keys_group::Group;
use super::super::keys_table::all;
use super::super::metrics::{BODY_PX, CARD_PAD, TITLE_PX};
use super::super::text;
use super::geom::{column, panel, GROUP_GAP, ROW_H, TITLE_H};
use super::row;

// Which groups fall in which column, left first.
const COLUMNS: [&[Group]; 2] = [&[Group::Move, Group::Sort], &[Group::Filter, Group::Act]];

/// The window behind stays readable through the theme's scrim rather than
/// being hidden. A reader opening this is checking a key against what is on
/// screen, so blanking the table would make them close the panel to remember
/// what they were doing. The panel is a toolkit card over the scrim.
pub fn paint(fb: &mut PaintBuffer, fb_w: u32, fb_h: u32) {
    let r = roles();
    fb.blend_rect(0, 0, fb_w, fb_h, r.scrim.argb());
    let (x, y, w, h) = panel(fb_w, fb_h);
    Card::new().draw(fb, Rect { x, y, w, h });

    let top = text::centred_top(y + CARD_PAD, TITLE_H, TITLE_PX);
    text::left(fb, x + CARD_PAD, top, b"KEYBOARD", r.text, TITLE_PX);
    let foot = text::centred_top(y + h.saturating_sub(TITLE_H), TITLE_H, BODY_PX);
    text::left(fb, x + CARD_PAD, foot, b"? or Esc closes this", r.muted, BODY_PX);

    let body = y + CARD_PAD + TITLE_H;
    for (i, groups) in COLUMNS.iter().enumerate() {
        let (cx, cw) = column(x, w, i as u32);
        render(fb, cx, body, cw, groups);
    }
}

// One column: each group under its heading, in table order.
fn render(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, groups: &[Group]) {
    let (muted, mut row_y) = (roles().muted, y);
    for group in groups {
        let top = text::centred_top(row_y, ROW_H, BODY_PX);
        text::left(fb, x, top, group.label(), muted, BODY_PX);
        row_y += ROW_H;
        for b in all().filter(|b| b.group == *group) {
            row::paint(fb, x, row_y, w, b.key, b.label);
            row_y += ROW_H;
        }
        row_y += GROUP_GAP;
    }
}
