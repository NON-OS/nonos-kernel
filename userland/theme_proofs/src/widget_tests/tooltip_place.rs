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

//! Tooltip placement: from an anchor at every corner, edge and the centre of
//! its bounds, `place` keeps the tooltip whole inside them, centred on the
//! anchor unless an edge stops it, above by default and below after
//! `.below()`, on the other side where there is no room. With no room on
//! either side, or bounds too small for it, it stays inside them.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::CONTROL_H;
use nonos_toolkit::widgets::{Rect, Tooltip};

use super::placing::{anchors, fault, Side};
use super::serial::{serial, SCALES};
use super::tooltip::TEXTS;

/// Places every text, preferring either side, from the anchors in the bounds
/// `case` gives for its size, and asserts each opens on `side(row, pref)`.
fn assert_placed(case: impl Fn((u32, u32)) -> (Rect, u32), side: impl Fn(usize, Side) -> Side) {
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        let tips = TEXTS.map(Tooltip::new);
        let both = tips.into_iter().flat_map(|t| [(t, Side::Above), (t.below(), Side::Below)]);
        for (t, pref) in both {
            let (bounds, a) = case(t.size());
            for (anchor, row) in anchors(bounds, a) {
                let want = side(row, pref);
                let why = fault(t.place(anchor, bounds), t.size(), anchor, bounds, want);
                fails.extend(why.map(|y| format!("{t:?} {want:?} at {q}/4 by {anchor:?}: {y}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn tooltip_opens_on_the_side_with_room() {
    let _g = serial();
    let roomy =
        |_| (Rect { x: 40, y: 30, w: scale().px(400), h: scale().px(240) }, scale().px(CONTROL_H));
    assert_placed(roomy, |row, pref| [Side::Below, pref, Side::Above][row]);
}

/// Bounds as shares of the tooltip's size, `(w over, w under, h over, h
/// under)`: twice as wide and half as tall again, so no anchor has room on
/// either side; its own size; half its size; and a quarter as tall.
const TIGHT: [(u32, u32, u32, u32); 4] = [(2, 1, 3, 2), (1, 1, 1, 1), (1, 2, 1, 2), (1, 1, 1, 4)];

#[test]
fn tooltip_stays_inside_bounds_with_no_room_by_the_anchor() {
    let _g = serial();
    for (wn, wd, hn, hd) in TIGHT {
        let at = move |(w, h): (u32, u32)| Rect { x: 40, y: 30, w: w * wn / wd, h: h * hn / hd };
        let case = move |size: (u32, u32)| (at(size), size.1 / 2);
        assert_placed(case, |_, _| Side::Free);
    }
}
