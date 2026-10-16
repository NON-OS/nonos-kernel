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

//! Tabs: the index `hit` returns is the tab whose segment was painted, for
//! the hover wash and for the selected look alike.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Rect, Tabs};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::serial::{serial, SCALES};
use super::tabs::{LABELS, LONGS};

/// A line for the first pixel that differs between `t` and `plain` which
/// `hit` does not give as tab `i`.
fn misnamed(t: Tabs, plain: Tabs, at: Rect, i: usize) -> Option<String> {
    let draw = |t: Tabs| Canvas::new(at, 0).painted(|fb| t.draw(fb, at));
    let lit = draw(t).diff(&draw(plain));
    let wrong = lit.into_iter().find(|&(x, y)| t.hit(at, x as i32, y as i32) != Some(i));
    wrong.map(|(x, y)| {
        format!("tab {i} in {at:?}: ({x}, {y}) hits {:?}", t.hit(at, x as i32, y as i32))
    })
}

#[test]
fn tabs_hit_names_the_tab_that_was_painted() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for labels in [&LABELS[..], &LONGS[..]] {
            let plain = Tabs::new(labels, usize::MAX);
            for at in boxes(plain.size()) {
                for i in 0..labels.len() {
                    fails.extend(misnamed(plain.hovered(Some(i)), plain, at, i));
                    fails.extend(misnamed(Tabs::new(labels, i), plain, at, i));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
