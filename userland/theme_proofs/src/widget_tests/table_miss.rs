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

//! Table: `hit` gives `None` outside the box, on the hairline under the
//! header, in the body below the last row, and anywhere in a disabled
//! table, and a header or a row everywhere else in the box.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::TABLE_ROW_H;
use nonos_toolkit::widgets::{Cell, State, Table};

use super::boxes::boxes;
use super::serial::{serial, SCALES};
use super::table::{COLS, ROWS};

#[test]
fn table_hits_nothing_outside_on_the_rule_or_below_the_rows() {
    let _g = serial();
    let off = State { disabled: true, ..State::default() };
    for q in SCALES {
        set_scale(q);
        let (row, hair) = (scale().px(TABLE_ROW_H), scale().hair());
        for (name, cols) in COLS {
            let t = Table::new(cols).rows(&ROWS[..3]).first(7);
            for at in boxes(t.size()) {
                let (x0, y0) = (at.x as i32, at.y as i32);
                let (x1, y1) = (x0 + at.w as i32, y0 + at.h as i32);
                let rows_end = y0 + (row + hair + row * 3) as i32;
                for y in (y0 - 3..y1 + 3).step_by(3).chain([y0 + row as i32, rows_end]) {
                    for x in (x0 - 3..x1 + 3).step_by(5).chain([x1 - 1, x1]) {
                        let inside = (x0..x1).contains(&x) && (y0..y1).contains(&y);
                        let band = (y - y0) / row as i32;
                        let want = match () {
                            _ if !inside || y >= rows_end => None,
                            _ if band == 0 => Some("header"),
                            _ if y - y0 < (row + hair) as i32 => None,
                            _ => Some("row"),
                        };
                        let got = t.hit(at, x, y).map(|c| match c {
                            Cell::Header(_) => "header",
                            Cell::Row { row: r, .. } => ["row", "wrong row"][usize::from(r < 7)],
                        });
                        assert_eq!(got, want, "{name} {x},{y} in {at:?} at {q}/4");
                        assert_eq!(t.state(off).hit(at, x, y), None, "{name} disabled {x},{y}");
                    }
                }
            }
        }
    }
    set_scale(SCALES[0]);
}
