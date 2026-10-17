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

//! Table: on a plain row, a striped one, and each of them selected, hovered,
//! pressed, selected and hovered, and all three, every cell reads at 4.5:1,
//! whole or cut with `…`; the titles, plain and sorted, at 4.5:1 and the
//! sort chevron at 3:1, in every scheme and high contrast, read back from
//! the pixels drawn. In a disabled table they need only be drawn visibly.

use nonos_toolkit::widgets::{Col, State, Table};

use super::hide::Hide;
use super::legible::{assert_legible_in, Off, Read};
use super::samples::LONG;
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

static COLS: [Col; 2] = [Col::new("Name").fixed(150), Col::new("Größe").fixed(110).right()];
static BLANK: [Col; 2] = [Col::new("").fixed(150), Col::new("Größe").fixed(110).right()];
static ROWS: [&[&str]; 3] = [&["Zeile Ä", "1,5 KiB"], &["Grüße 日本", "880 B"], &[LONG, "x"]];

/// The table with row `i` lit in each way the proofs read.
fn looks(i: usize) -> [(&'static str, Table<'static>); 6] {
    let t = Table::new(&COLS).rows(&ROWS);
    let (s, h, p) = (t.selected(Some(i)), t.hovered(Some(i)), t.pressed(Some(i)));
    let (sh, all) = (s.hovered(Some(i)), s.hovered(Some(i)).pressed(Some(i)));
    [("plain", t), ("selected", s), ("hovered", h), ("pressed", p), ("both", sh), ("all", all)]
}

/// Every ink to read.
fn reads() -> Vec<Read<Table<'static>>> {
    let read = |what: String, on, off, floor| Read { what: what.leak(), on, off, floor };
    let hide = |s: &'static str| Off::Hide(Hide::Text(s));
    let mut all = Vec::new();
    for (i, ground) in [(0, "plain row"), (1, "striped row")] {
        for (look, on) in looks(i) {
            for cell in ROWS[i] {
                all.push(read(format!("{ground} {look}: {cell}"), on, hide(cell), BODY));
            }
        }
    }
    let t = Table::new(&COLS).rows(&ROWS);
    all.push(read("cut cell".into(), t, hide(LONG), BODY));
    all.push(read("title".into(), t, hide("Name"), BODY));
    all.push(read("sorted title".into(), t.sort(1, false), hide("Größe"), BODY));
    let blank = Table::new(&BLANK).rows(&ROWS);
    all.push(read("sort chevron".into(), blank.sort(0, true), Off::Widget(blank), LARGE));
    all
}

#[test]
fn table_cells_titles_and_chevron_read_on_every_row() {
    let _g = serial();
    let off = State { disabled: true, ..State::default() };
    assert_legible_in(&reads(), || [State::default(), off].into_iter());
}
