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

//! Menu: the index `hit` gives is the row whose hover wash or held fill was
//! painted there, and a separator or disabled row takes neither.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Menu, Rect};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::menu::MENUS;
use super::serial::{serial, SCALES};

/// A line for the first of about 128 pixels, spread evenly through those
/// `lit` changes from `m`, the last among them, that `hit` does not give as
/// row `i`, or for a dead row that changed, or a live one that did not.
fn misnamed(m: Menu, lit: Menu, at: Rect, i: usize, live: bool) -> Option<String> {
    let draw = |m: Menu| Canvas::new(at, 0).painted(|fb| m.draw(fb, at));
    let changed = draw(lit).diff(&draw(m));
    if changed.is_empty() == live {
        return Some(format!("row {i} in {at:?}: live {live}, {} changed", changed.len()));
    }
    let hit = |&(x, y): &(u32, u32)| m.hit(at, x as i32, y as i32);
    let step = changed.len().div_ceil(128).max(1);
    let mut probes = changed.iter().step_by(step).chain(changed.last());
    let wrong = probes.find(|p| hit(p) != Some(i)).copied();
    wrong.map(|p| format!("row {i} in {at:?}: {p:?} hits {:?}", hit(&p)))
}

#[test]
fn menu_hit_names_the_row_that_was_painted() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, items) in MENUS {
            let m = Menu::new(items);
            for at in boxes(m.size()) {
                for (i, it) in items.iter().enumerate() {
                    for lit in [m.hovered(Some(i)), m.pressed(Some(i))] {
                        let what = |e| format!("{name} at {q}/4 {e}");
                        fails.extend(misnamed(m, lit, at, i, it.live()).map(what));
                    }
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
