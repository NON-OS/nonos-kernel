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

//! Menu placement: from an anchor at every corner, edge and the centre of
//! its bounds, `place` keeps every menu whole inside them, at the anchor's
//! left edge unless the right edge of the bounds pushes it left, below the
//! anchor, and above it where there is no room below. With no room on
//! either side, or bounds too small for it, it stays inside them.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::CONTROL_H;
use nonos_toolkit::widgets::{Menu, Rect};

use super::menu::MENUS;
use super::placing::{anchors, fault, Across, Side};
use super::serial::{serial, SCALES};

/// Places every menu from the anchors in the bounds `case` gives for its
/// size, and asserts each opens on `side(row)` at the anchor's left edge.
fn assert_placed(case: impl Fn((u32, u32)) -> (Rect, u32), side: impl Fn(usize) -> Side) {
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, items) in MENUS {
            let m = Menu::new(items);
            let (bounds, a) = case(m.size());
            for (anchor, row) in anchors(bounds, a) {
                let how = (side(row), Across::Left);
                let why = fault(m.place(anchor, bounds), m.size(), anchor, bounds, how);
                fails.extend(why.map(|y| format!("{name} {how:?} at {q}/4 by {anchor:?}: {y}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn menu_opens_below_and_flips_above_at_the_bottom() {
    let _g = serial();
    let roomy = |(w, h): (u32, u32)| {
        let a = scale().px(CONTROL_H);
        (Rect { x: 40, y: 30, w: w * 2 + a, h: h * 2 + a + 2 }, a)
    };
    assert_placed(roomy, |row| [Side::Below, Side::Below, Side::Above][row]);
}

/// Bounds as shares of the menu's size, `(w over, w under, h over, h
/// under)`: twice as wide and half as tall again, so no anchor has room on
/// either side; its own size; half its size; and a quarter as tall.
const TIGHT: [(u32, u32, u32, u32); 4] = [(2, 1, 3, 2), (1, 1, 1, 1), (1, 2, 1, 2), (1, 1, 1, 4)];

#[test]
fn menu_stays_inside_bounds_with_no_room_by_the_anchor() {
    let _g = serial();
    for (wn, wd, hn, hd) in TIGHT {
        let at = move |(w, h): (u32, u32)| Rect { x: 40, y: 30, w: w * wn / wd, h: h * hn / hd };
        let case = move |size: (u32, u32)| (at(size), size.1 / 2);
        assert_placed(case, |_| Side::Free);
    }
}
