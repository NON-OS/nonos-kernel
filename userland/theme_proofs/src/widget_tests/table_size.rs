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

//! Table: its height adds up the header, the hairline under it and
//! `TABLE_ROW_H` per given row, its width the fixed columns and
//! `TABLE_COL_MIN` per shared one, and it draws the same in every state but
//! `disabled`, the one flag it reads.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::{TABLE_COL_MIN, TABLE_ROW_H};
use nonos_toolkit::widgets::{State, Table};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::serial::{serial, SCALES};
use super::states::states;
use super::table::{row_sets, tables, FIXED, MIXED, ONE};

#[test]
fn table_size_adds_up_its_header_rows_and_columns() {
    let _g = serial();
    for q in SCALES {
        set_scale(q);
        let (s, w) = (scale(), |t: Table| t.size().0);
        let (row, min) = (s.px(TABLE_ROW_H), s.px(TABLE_COL_MIN));
        for (name, rows) in row_sets() {
            let want = row + s.hair() + row * rows.len() as u32;
            assert_eq!(Table::new(&MIXED).rows(rows).size().1, want, "{name} at {q}/4");
        }
        assert_eq!(w(Table::new(&MIXED)), s.px(56) + s.px(84) + min * 2, "mixed at {q}/4");
        assert_eq!(w(Table::new(&FIXED)), s.px(90) + s.px(120), "fixed at {q}/4");
        assert_eq!(w(Table::new(&ONE)), min, "one at {q}/4");
        assert_eq!(Table::new(&[]).size(), (0, row + s.hair()), "no columns at {q}/4");
    }
    set_scale(SCALES[0]);
}

#[test]
fn table_draws_alike_in_every_state_but_disabled() {
    let _g = serial();
    for (name, t) in tables().into_iter().step_by(5) {
        let at = boxes(t.size())[0];
        let draw = |st: State| Canvas::new(at, 0).painted(|fb| t.state(st).draw(fb, at)).px;
        let off = State { disabled: true, ..State::default() };
        let (live, off) = (draw(State::default()), draw(off));
        assert!(live != off, "{name}: disabled changes nothing");
        for st in states() {
            let want = if st.disabled { &off } else { &live };
            assert!(draw(st) == *want, "{name} {st:?}");
        }
    }
}
