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

//! Dialog: the index `hit` gives is the button whose own `Button::hit` takes
//! the point on the rect the dialog drew it in, found from the pixels its
//! hover, press and focus change; the panel, title, body, note and scrim
//! give `None`, and so does every point of a disabled dialog.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Button, Dialog, Rect, State, Tone};

use super::boxes::boxes;
use super::dialog::{Buttons, BODIES, NOTE, SETS};
use super::dialog_row::drawn;
use super::hits::around;
use super::serial::{serial, SCALES};

/// Either side of each edge of `r`, at nine points along each.
fn ring(r: &Rect) -> Vec<(i32, i32)> {
    let (x0, y0, x1, y1) = (r.x as i32, r.y as i32, (r.x + r.w) as i32, (r.y + r.h) as i32);
    let along = |a: i32, b: i32| (0..9).map(move |k| a - 1 + (b - a + 1) * k / 8);
    let across = along(x0, x1).flat_map(|x| [y0 - 1, y0, y1 - 1, y1].map(|y| (x, y)));
    across.chain(along(y0, y1).flat_map(|y| [x0 - 1, x0, x1 - 1, x1].map(|x| (x, y)))).collect()
}

/// A 13 by 13 grid over `at`, the rings of `rects`, and round `at`.
fn probes(at: Rect, rects: &[Option<Rect>]) -> Vec<(i32, i32)> {
    let (x0, y0, w, h) = (at.x as i32, at.y as i32, at.w as i32, at.h as i32);
    let grid = (0..13).flat_map(|j| (0..13).map(move |i| (x0 + w * i / 12, y0 + h * j / 12)));
    let corners = around(at).into_iter().take(9);
    grid.chain(rects.iter().flatten().flat_map(ring)).chain(corners).collect()
}

/// The first probe where `hit` is not the hit of the button drawn there,
/// or where the disabled dialog hits anything.
fn wrong(d: Dialog, set: Buttons, at: Rect) -> Option<String> {
    let rects: Vec<_> = (0..set.len()).map(|i| drawn(d, i, at)).collect();
    let own = |i: usize| Button::new(set[i].0).kind(set[i].1);
    let want = |x, y| (0..set.len()).find(|&i| rects[i].is_some_and(|r| own(i).hit(r, x, y)));
    let off = d.state(State { disabled: true, ..State::default() });
    let bad = |&(x, y): &(i32, i32)| d.hit(at, x, y) != want(x, y) || off.hit(at, x, y).is_some();
    let bad = probes(at, &rects).into_iter().find(bad);
    bad.map(|(x, y)| format!("{x}, {y} hits {:?} against {rects:?}", d.hit(at, x, y)))
}

#[test]
fn dialog_hit_is_each_buttons_own_hit_and_nothing_else() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for set in SETS {
            let d = Dialog::new("Delete?").body(BODIES[1]).note(NOTE, Tone::Warn).buttons(set);
            for at in boxes(d.size()) {
                fails.extend(wrong(d, set, at).map(|e| format!("{set:?} at {q}/4 in {at:?}: {e}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
