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

//! Table: each cell's ink, long and multi-byte ones among them, lands only
//! where `hit` names that cell's row and column, so a long cell is cut and
//! never drawn over its neighbour, and a cell past the last column is not
//! drawn at all.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Cell, Table};

use super::boxes::boxes;
use super::serial::{serial, SCALES};
use super::table::{COLS, ROWS};
use super::table_probe::misnamed;

/// `ROWS` with every cell blank but row `k`'s cell in column `c`.
fn alone(k: usize, c: usize) -> Vec<Vec<&'static str>> {
    let blank = |(i, row): (usize, &&[&'static str])| {
        let cell = |(j, s): (usize, &&'static str)| if (i, j) == (k, c) { *s } else { "" };
        row.iter().enumerate().map(cell).collect()
    };
    ROWS.iter().enumerate().map(blank).collect()
}

#[test]
fn table_cells_stay_in_their_own_column() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, cols) in COLS {
            let held: Vec<Vec<Vec<&str>>> =
                (0..ROWS.len() * 5).map(|n| alone(n / 5, n % 5)).collect();
            let rows: Vec<Vec<&[&str]>> =
                held.iter().map(|r| r.iter().map(Vec::as_slice).collect()).collect();
            let none = alone(usize::MAX, 0);
            let none: Vec<&[&str]> = none.iter().map(Vec::as_slice).collect();
            let blank = Table::new(cols).rows(&none).first(2);
            for at in boxes(blank.size()) {
                for (n, lit) in rows.iter().enumerate() {
                    let (k, c) = (n / 5, n % 5);
                    let live = c < cols.len() && ROWS[k].get(c).is_some_and(|s| !s.is_empty());
                    let named = |cell, _| live && cell == Cell::Row { row: k + 2, col: c };
                    let what = format!("{name} cell {k},{c} at {q}/4");
                    let lit = (blank, blank.rows(lit), at, live && at.w >= blank.size().0);
                    fails.extend(misnamed(&what, lit, named));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
