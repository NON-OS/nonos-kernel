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

//! Table: the columns, rows and lit tables the table proofs draw.

use nonos_toolkit::widgets::{Col, Table};

use super::samples::LONG;

/// A shared name, a fixed numeric and a fixed word column, and a numeric
/// column taking two shares, like the Process Manager's.
pub(crate) const MIXED: [Col; 4] = [
    Col::new("Name"),
    Col::new("PID").fixed(56).right(),
    Col::new("Zustand").fixed(84),
    Col::new("Speicher").share(2).right(),
];

/// Fixed columns only, so the last takes what is left.
pub(crate) const FIXED: [Col; 2] = [Col::new("Schlüssel").fixed(90), Col::new("Wert").fixed(120)];

/// One shared column with a title too long for it.
pub(crate) const ONE: [Col; 1] = [Col::new(LONG)];

/// Rows with short, long and multi-byte cells, a row short of cells and a
/// row with a cell past the last column.
pub(crate) const ROWS: [&[&str]; 7] = [
    &["init", "1", "läuft", "1,2 MiB"],
    &[LONG, "4242424242", LONG, LONG],
    &["Grüße — 日本語", "17", "schläft", "880 KiB"],
    &["a🙂b🙂c", "3"],
    &["naïve café", "99", "wartet", "12 MiB", "extra"],
    &["ééééééééééééé", "1234567", "läuft", "0 B"],
    &["", "", "", ""],
];

/// The column sets the proofs draw, by name.
pub(crate) const COLS: [(&str, &[Col]); 3] = [("mixed", &MIXED), ("fixed", &FIXED), ("one", &ONE)];

/// No rows, one row and every row.
pub(crate) fn row_sets() -> [(&'static str, &'static [&'static [&'static str]]); 3] {
    [("no rows", &[]), ("one row", &ROWS[..1]), ("many rows", &ROWS)]
}

/// Nothing lit; a sort with three rows lit apart; one row sorted down and
/// selected, hovered and pressed at once with `first` past the start; and
/// indices past the end.
fn lit(t: Table<'static>) -> [(&'static str, Table<'static>); 4] {
    let apart = t.sort(0, true).selected(Some(0)).hovered(Some(1)).pressed(Some(2));
    let all = t.sort(1, false).first(3).selected(Some(4)).hovered(Some(4)).pressed(Some(4));
    let past = t.sort(9, true).selected(Some(99)).hovered(Some(7)).pressed(Some(100));
    [("plain", t), ("apart", apart), ("all on one", all), ("past the end", past)]
}

/// Every column set with every row set in every lit form.
pub(crate) fn tables() -> Vec<(String, Table<'static>)> {
    let sets = COLS.into_iter().flat_map(|c| row_sets().map(move |r| (c, r)));
    let named = |((c, cols), (r, rows)): ((&str, &'static [Col]), (&str, _))| {
        lit(Table::new(cols).rows(rows)).map(move |(how, t)| (format!("{c}, {r}, {how}"), t))
    };
    sets.flat_map(named).collect()
}
