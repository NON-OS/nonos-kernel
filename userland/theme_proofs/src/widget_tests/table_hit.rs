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

//! Table: a header hit names the column whose title and chevron were lit
//! there by a sort, and a row hit names the row, counted from `first`,
//! whose hover wash was painted there, in the column whose header is above.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Cell, Table};

use super::boxes::boxes;
use super::serial::{serial, SCALES};
use super::table::{COLS, ROWS};
use super::table_probe::misnamed;

#[test]
fn table_hit_names_the_header_and_row_that_were_painted() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for ((name, cols), first) in COLS.into_iter().zip([0, 5, 1_000_000]) {
            let t = Table::new(cols).rows(&ROWS).first(first);
            for at in boxes(t.size()) {
                let head = |x: i32| t.hit(at, x, at.y as i32);
                for c in 0..cols.len() {
                    let lit = (t, t.sort(c, c % 2 == 0), at, at.w >= t.size().0);
                    let what = format!("{name} header {c} at {q}/4");
                    fails.extend(misnamed(&what, lit, |cell, _| cell == Cell::Header(c)));
                }
                for row in first..first + ROWS.len() {
                    let named = |cell, x| matches!(head(x), Some(Cell::Header(col)) if cell == Cell::Row { row, col });
                    let what = format!("{name} row {row} at {q}/4");
                    fails.extend(misnamed(&what, (t, t.hovered(Some(row)), at, true), named));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
