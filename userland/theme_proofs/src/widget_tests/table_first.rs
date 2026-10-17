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

//! Table: scrolled to row `k` by passing the rows from `k` with `first(k)`,
//! a table keeps its header and paints each row exactly as the whole list
//! paints it, stripe, selection, hover and press included, `k` rows higher,
//! and its hits name the same rows of the whole list.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::TABLE_ROW_H;
use nonos_toolkit::widgets::{Cell, Table};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::serial::{serial, SCALES};
use super::table::{MIXED, ROWS};

#[test]
fn table_scrolled_by_first_paints_and_hits_the_whole_lists_rows() {
    let _g = serial();
    for q in SCALES {
        set_scale(q);
        let s = scale();
        let whole = Table::new(&MIXED).rows(&ROWS).sort(0, true);
        let whole = whole.selected(Some(3)).hovered(Some(4)).pressed(Some(5));
        let at = boxes(whole.size())[0];
        let (row, top) = (s.px(TABLE_ROW_H), at.y + s.px(TABLE_ROW_H) + s.hair());
        let all = Canvas::new(at, 0).painted(|fb| whole.draw(fb, at));
        let line = |c: &Canvas, y: u32| c.px[(y * c.w) as usize..((y + 1) * c.w) as usize].to_vec();
        for k in 0..ROWS.len() {
            let part = whole.rows(&ROWS[k..]).first(k);
            let some = Canvas::new(at, 0).painted(|fb| part.draw(fb, at));
            for y in 0..top {
                assert_eq!(line(&some, y), line(&all, y), "header line {y} from {k} at {q}/4");
            }
            for y in top..top + row * (ROWS.len() - k) as u32 {
                let was = y + row * k as u32;
                assert_eq!(line(&some, y), line(&all, was), "line {y} from {k} at {q}/4");
                let (x, y, was) = (at.x as i32 + 1, y as i32, was as i32);
                let want = Some(Cell::Row { row: k + ((y as u32 - top) / row) as usize, col: 0 });
                assert_eq!(part.hit(at, x, y), want, "hit at {y} from {k} at {q}/4");
                assert_eq!(whole.hit(at, x, was), want, "whole hit at {was} at {q}/4");
            }
        }
    }
    set_scale(SCALES[0]);
}
