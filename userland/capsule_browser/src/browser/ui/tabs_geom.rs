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

use super::rect::Rect;

pub const LIGHTS_RESERVE: i32 = 128;
pub const TAB_W: i32 = 200;
pub const TAB_MIN: i32 = 120;
pub const TAB_H: i32 = 32;
pub const PLUS: i32 = 32;
const GAP: i32 = 4;
const CLOSE: i32 = 18;
const CLOSE_PAD: i32 = 6;

/// `n` tabs in a `w` x `h` titlebar accessory; painter and hit-test share it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Strip {
    pub n: usize,
    pub active: usize,
    pub w: i32,
    pub h: i32,
}

/// Width the strip asks for when every tab gets its full width.
pub fn nominal_w(n: usize) -> i32 {
    n as i32 * (TAB_W + GAP) + PLUS
}

/// `(first, count)` of the tabs shown: as many as fit at `TAB_MIN`, slid to keep the active one.
pub fn visible(s: &Strip) -> (usize, usize) {
    let count = s.n.min(((s.w - PLUS) / (TAB_MIN + GAP)).max(1) as usize);
    let first = (s.active + 1).saturating_sub(count).min(s.n - count);
    (first, count)
}

fn tab_w(s: &Strip, count: usize) -> i32 {
    let room = s.w - PLUS - count as i32 * GAP;
    (room / count.max(1) as i32).clamp(0, TAB_W)
}

pub fn tab_rect(s: &Strip, i: usize) -> Option<Rect> {
    let (first, count) = visible(s);
    if i < first || i >= first + count {
        return None;
    }
    let (tw, th) = (tab_w(s, count), TAB_H.min(s.h));
    Some(Rect::new((i - first) as i32 * (tw + GAP), (s.h - th) / 2, tw, th))
}

pub fn close_rect(tab: Rect) -> Rect {
    let c = CLOSE.min(tab.h);
    Rect::new(tab.right() - CLOSE_PAD - c, tab.y + (tab.h - c) / 2, c, c)
}

pub fn plus_rect(s: &Strip) -> Rect {
    let (_, count) = visible(s);
    let (x, th) = (count as i32 * (tab_w(s, count) + GAP), TAB_H.min(s.h));
    Rect::new(x, (s.h - th) / 2, PLUS.min(s.w - x).max(0), th)
}
