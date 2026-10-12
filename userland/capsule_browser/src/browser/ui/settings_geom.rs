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

use alloc::vec::Vec;

use super::list_geom::ListGeom;
use super::rect::Rect;
use super::settings_place::{place, Cursor};
pub use super::settings_rows::{Control, Field, Item, Kind, Line};
use super::settings_table::SECTIONS;

pub const BAND_H: i32 = 112;
const HEAD_H: i32 = 44;
const CARD_PAD: i32 = 6;
const SECTION_GAP: i32 = 20;
const BOTTOM: i32 = 32;

/// Where everything on the settings page sits, in content-local pixels.
/// The header band stays put; the sections under it move up by `scroll`.
/// The painter and the click handler build it the same way.
pub struct SettingsGeom {
    pub frame: Rect,
    pub title_y: i32,
    pub sub_y: i32,
    pub items: Vec<Item>,
    pub height: i32,
}

impl SettingsGeom {
    pub fn new(w: i32, h: i32, scroll: i32) -> Self {
        let list = ListGeom::new(w, h, 0);
        let frame = list.frame;
        let mut items = Vec::new();
        let top = BAND_H - scroll.max(0);
        let mut y = top;
        for (title, rows) in SECTIONS.iter() {
            items.push(Item {
                kind: Kind::Head(title),
                rect: Rect::new(frame.x, y, frame.w, HEAD_H),
            });
            y += HEAD_H;
            let card = items.len();
            items.push(Item { kind: Kind::Card, rect: Rect::default() });
            let mut at = Cursor { frame, y: y + CARD_PAD };
            for row in rows.iter() {
                place(&mut at, row, &mut items);
            }
            items[card].rect = Rect::new(frame.x, y, frame.w, at.y + CARD_PAD - y);
            y = at.y + CARD_PAD + SECTION_GAP;
        }
        let height = y - top + BAND_H + BOTTOM - SECTION_GAP;
        SettingsGeom { frame, title_y: list.title_y, sub_y: list.sub_y, items, height }
    }

    /// The control under `(x, y)`. Sections scrolled under the header band
    /// are covered by it, so nothing there hits.
    pub fn hit(&self, x: i32, y: i32) -> Option<Control> {
        if y < BAND_H {
            return None;
        }
        self.items.iter().find_map(|it| match it.kind {
            Kind::Ctl(c) if it.rect.contains(x, y) => Some(c),
            _ => None,
        })
    }

    /// Where `c` is drawn, if the page has it.
    pub fn rect(&self, c: Control) -> Option<Rect> {
        self.items.iter().find(|it| it.kind == Kind::Ctl(c)).map(|it| it.rect)
    }
}
