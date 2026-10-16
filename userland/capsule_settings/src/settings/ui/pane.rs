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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::widgets::Rect;

use crate::settings::schema::blocks_for;
use crate::settings::schema::rows::Row;
use crate::settings::state::State;

use super::card;
use super::metrics::PANE_PAD_X;
use super::net_rows;
use super::page_head;
use super::row;
use super::saved_rows;
use super::wallpaper_row;
use super::walk::{walk, Item};

/// Paints the section pane into `fb`, which is the window minus the sidebar.
/// Every rectangle comes from `walk`, the same walker the hit test uses.
pub fn paint(fb: &mut PaintBuffer, state: &State, scroll: u32, view_w: u32, view_h: u32) {
    let card_x = PANE_PAD_X;
    let card_w = view_w.saturating_sub(PANE_PAD_X * 2);
    let blocks = blocks_for(state.section);
    let cursor = state.cursor[state.section.index()];
    let mut field_index = 0usize;
    walk(state, |y, h, item| {
        let sy = y as i32 - scroll as i32;
        let offscreen = sy >= view_h as i32 || sy + h as i32 <= 0;
        if let Item::Row(bi, ri) = item {
            let r = &blocks[bi].rows[ri];
            let selected = matches!(r, Row::Field(_)) && field_index == cursor;
            if matches!(r, Row::Field(_)) {
                field_index += 1;
            }
            if offscreen {
                return;
            }
            row::paint(fb, state, r, scroll, Rect { x: card_x, y, w: card_w, h }, selected);
            if ri + 1 < blocks[bi].rows.len() {
                row::hairline(fb, scroll, card_x, card_w, y, h);
            }
            return;
        }
        if let Item::Wallpaper(i) = item {
            let selected = field_index == cursor;
            field_index += 1;
            if !offscreen {
                if selected {
                    super::row_focus::paint(fb, card_x, card_w, sy, h);
                }
                wallpaper_row::paint(fb, state, i, card_x, card_w, sy, h);
                row::hairline(fb, scroll, card_x, card_w, y, h);
            }
            return;
        }
        if offscreen {
            return;
        }
        match item {
            Item::Head => page_head::paint(fb, state.section, sy),
            Item::Card(bi) => {
                card::paint(fb, &blocks[bi], scroll, Rect { x: card_x, y, w: card_w, h })
            }
            Item::CardHead(bi) => card::paint_pill(fb, state, &blocks[bi], card_x, sy, card_w),
            Item::Network(i) => {
                net_rows::paint(fb, state, i, card_x, card_w, sy, h);
                row::hairline(fb, scroll, card_x, card_w, y, h);
            }
            Item::Saved(i) => {
                saved_rows::paint(fb, state, i, card_x, card_w, sy, h);
                row::hairline(fb, scroll, card_x, card_w, y, h);
            }
            Item::Row(..) | Item::Wallpaper(_) => {}
        }
    });
}
