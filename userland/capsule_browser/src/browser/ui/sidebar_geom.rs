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

use super::rect::Rect;
pub use super::sidebar_parts::{brand, divider, hit};

pub const ROW_H: i32 = 40;
const GAP: i32 = 2;
pub(super) const PAD: i32 = 12;
pub(super) const BRAND_H: i32 = 64;
pub(super) const DIVIDER: i32 = 17;

/// What a sidebar row stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    Start,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub rect: Rect,
    pub kind: RowKind,
}

const UPPER: [RowKind; 1] = [RowKind::Start];

fn row(rail: bool, side: Rect, y: i32, kind: RowKind) -> Row {
    let rect = match rail {
        true => Rect::new(side.x + (side.w - ROW_H) / 2, y, ROW_H, ROW_H),
        false => Rect::new(side.x + PAD, y, (side.w - 2 * PAD).max(0), ROW_H),
    };
    Row { rect, kind }
}

/// The page rows under the brand, then Settings anchored to the bottom. A
/// sidebar too short to hold them all pushes Settings below the last row
/// rather than over it.
pub fn rows(rail: bool, side: Rect) -> Vec<Row> {
    let step = ROW_H + GAP;
    let top = if rail { side.y + PAD } else { side.y + BRAND_H };
    let mut out: Vec<Row> =
        UPPER.iter().enumerate().map(|(i, k)| row(rail, side, top + i as i32 * step, *k)).collect();
    let after = top + UPPER.len() as i32 * step - GAP + DIVIDER;
    out.push(row(rail, side, (side.bottom() - PAD - ROW_H).max(after), RowKind::Settings));
    out
}
