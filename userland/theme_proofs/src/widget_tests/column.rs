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
//! Column: what it hands out is stacked in order inside its box, a gap apart,
//! and a column that runs out hands out empty rectangles, never past its edge.

use nonos_toolkit::widgets::{Column, Rect};

const AT: Rect = Rect { x: 16, y: 40, w: 300, h: 100 };

fn inside(r: Rect) -> bool {
    r.x >= AT.x && r.y >= AT.y && r.x + r.w <= AT.x + AT.w && r.y + r.h <= AT.y + AT.h
}

#[test]
fn rectangles_stack_in_order_a_gap_apart() {
    let mut c = Column::new(AT).gap(8);
    let a = c.next(20);
    let b = c.next(30);
    assert_eq!(a, Rect { x: 16, y: 40, w: 300, h: 20 });
    assert_eq!(b, Rect { x: 16, y: 68, w: 300, h: 30 });
    assert_eq!(c.rest(), Rect { x: 16, y: 106, w: 300, h: 34 });
}

#[test]
fn a_column_that_runs_out_never_reaches_past_its_box() {
    for gap in [0, 4, 37, 200] {
        let mut c = Column::new(AT).gap(gap);
        for h in [0, 1, 25, 60, 99, 500] {
            let r = c.next(h);
            assert!(inside(r), "gap {gap}, h {h}: {r:?}");
            assert!(inside(c.rest()), "gap {gap}, rest after {h}");
        }
        assert_eq!(c.next(10).h, 0, "gap {gap}: nothing left to hand out");
        assert_eq!(c.rest().y + c.rest().h, AT.y + AT.h);
    }
}

#[test]
fn what_is_handed_out_and_what_is_left_tile_the_box() {
    let mut c = Column::new(AT);
    let total: u32 = [10, 20, 30].iter().map(|&h| c.next(h).h).sum();
    assert_eq!(total + c.rest().h, AT.h);
}
