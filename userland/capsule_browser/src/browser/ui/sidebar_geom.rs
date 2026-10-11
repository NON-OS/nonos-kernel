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

use super::group_rows;
use super::rect::Rect;
use super::sidebar_parts::section;
pub use super::sidebar_parts::{brand, dividers, groups_head, hit};

pub const ROW_H: i32 = 40;
pub(super) const GAP: i32 = 2;
pub(super) const PAD: i32 = 12;
pub(super) const BRAND_H: i32 = 64;
pub(super) const DIVIDER: i32 = 17;

/// What a sidebar row stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    Start,
    Tabs,
    Bookmarks,
    Reader,
    Downloads,
    History,
    Settings,
    AllTabs,
    Group(usize),
    NewGroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub rect: Rect,
    pub kind: RowKind,
}

pub const ROWS: usize = 7;
pub(super) const UPPER: [RowKind; 2] = [RowKind::Start, RowKind::Tabs];
pub(super) const LOWER: [RowKind; 4] =
    [RowKind::Bookmarks, RowKind::Reader, RowKind::Downloads, RowKind::History];

fn row(rail: bool, side: Rect, y: i32, kind: RowKind) -> Row {
    let rect = match rail {
        true => Rect::new(side.x + (side.w - ROW_H) / 2, y, ROW_H, ROW_H),
        false => Rect::new(side.x + PAD, y, (side.w - 2 * PAD).max(0), ROW_H),
    };
    Row { rect, kind }
}

/// Start and Tabs, the Tab Groups section in the full sidebar, a divider,
/// the four library rows, and Settings anchored to the bottom. A sidebar too
/// short to hold them all pushes Settings below the last library row rather
/// than over it. The section's rows follow Settings in the list; a section
/// short of room lists only the first groups that fit.
pub fn rows(rail: bool, side: Rect, groups: usize) -> Vec<Row> {
    let step = ROW_H + GAP;
    let (gtop, shown) = section(rail, side, groups);
    let top = gtop - UPPER.len() as i32 * step;
    let lower_top = gtop + shown.map_or(0, group_rows::height) + DIVIDER;
    let mut out = Vec::with_capacity(ROWS + groups + 2);
    for (i, k) in UPPER.iter().enumerate() {
        out.push(row(rail, side, top + i as i32 * step, *k));
    }
    for (i, k) in LOWER.iter().enumerate() {
        out.push(row(rail, side, lower_top + i as i32 * step, *k));
    }
    let after = lower_top + LOWER.len() as i32 * step - GAP + DIVIDER;
    out.push(row(rail, side, (side.bottom() - PAD - ROW_H).max(after), RowKind::Settings));
    if let Some(n) = shown {
        out.extend(group_rows::rows(side.x + PAD, side.w - 2 * PAD, gtop, n));
    }
    out
}
