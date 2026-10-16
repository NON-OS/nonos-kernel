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

//! Row: `trailing_rect` lies in the box, and the row leaves it free for the
//! app's own control.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Rect;

use super::boxes::{boxes, inside, within};
use super::hits::drawn;
use super::row::variants;
use super::serial::{serial, SCALES};

#[test]
fn row_trailing_rect_is_in_the_box_and_left_free() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, row) in variants() {
            for at in boxes(row.size()) {
                let free: Rect = row.trailing_rect(at);
                if !within(free, at) {
                    fails.push(format!("{name} at {q}/4: {free:?} outside {at:?}"));
                }
                let ink = drawn(row, at).into_iter().find(|&p| inside(free, p));
                fails.extend(ink.map(|p| format!("{name} at {q}/4: drew {p:?} in {free:?}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
