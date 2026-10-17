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

//! Dialog: `next_focus` steps right for Tab and left for Shift-Tab, wrapping,
//! from any button or past the last, by any step, and is `None` with no
//! button. `pointer` lights the button under it, holds it only while a press
//! begun on it stays there, and a finger holds without hover.

use std::iter::successors;

use nonos_toolkit::widgets::{Dialog, Pointer, Rect};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::dialog::{BODIES, THREE};
use super::dialog_row::drawn;
use super::serial::serial;

#[test]
fn dialog_next_focus_wraps_both_ways() {
    let next = Dialog::next_focus;
    let walk = |step| successors(Some(0), |&f| next(3, f, step)).take(7).collect::<Vec<_>>();
    assert_eq!(walk(1), [0, 1, 2, 0, 1, 2, 0], "Tab");
    assert_eq!(walk(-1), [0, 2, 1, 0, 2, 1, 0], "Shift-Tab");
    assert_eq!((next(3, 9, 1), next(3, 9, -1), next(3, 1, 0)), (Some(0), Some(2), Some(1)));
    assert_eq!((next(3, 0, 4), next(3, 0, -4), next(1, 0, -1)), (Some(1), Some(2), Some(0)));
    for (count, from) in (1..5).flat_map(|c| (0..7).map(move |f| (c, f))) {
        for step in (-9..=9).chain([i32::MIN, i32::MAX]) {
            let got = next(count, from, step);
            assert!(got.is_some_and(|i| i < count), "{count} from {from} by {step}: {got:?}");
        }
    }
    for (from, step) in [(0, 0), (0, 1), (5, -1), (usize::MAX, i32::MIN)] {
        assert_eq!(next(0, from, step), None, "no button, from {from} by {step}");
    }
}

#[test]
fn dialog_pointer_lights_the_button_it_is_over() {
    let _g = serial();
    let d = Dialog::new("Delete?").body(BODIES[0]).buttons(THREE);
    let at = boxes(d.size())[1];
    let mid = |r: Rect| ((r.x + r.w / 2) as i32, (r.y + r.h / 2) as i32);
    let b = [0, 1, 2].map(|i| drawn(d, i, at).map_or((0, 0), mid));
    let paint = |d: Dialog| Canvas::new(at, 0).painted(|fb| d.draw(fb, at)).px;
    let mut p = Pointer::new();
    assert!(paint(d.pointer(&p, at)) == paint(d), "unseen");
    let moved: fn(&mut Pointer, i32, i32) = Pointer::moved;
    let steps = [
        (moved, b[1], Some(1), None, "over 1"),
        (Pointer::pressed, b[1], Some(1), Some(1), "pressed on 1"),
        (moved, b[2], Some(2), None, "dragged to 2"),
        (moved, b[1], Some(1), Some(1), "back on 1"),
        (|p, _, _| p.released(), b[1], Some(1), None, "released on 1"),
        (moved, mid(Rect { w: 2, h: 2, ..at }), None, None, "on the scrim"),
        (Pointer::touched, b[0], None, Some(0), "a finger on 0"),
    ];
    for (act, (x, y), h, q, what) in steps {
        act(&mut p, x, y);
        assert!(paint(d.pointer(&p, at)) == paint(d.hovered(h).pressed(q)), "{what}");
    }
}
