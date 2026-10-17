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
//! Pointer: hover follows the pointer, a press counts only on the widget it
//! began on, and a touch presses without hovering.

use nonos_toolkit::widgets::rect::contains;
use nonos_toolkit::widgets::{Pointer, Rect, State};

const A: Rect = Rect { x: 10, y: 10, w: 40, h: 20 };
const B: Rect = Rect { x: 60, y: 10, w: 40, h: 20 };

fn on(p: &Pointer, r: Rect) -> State {
    p.state(|x, y| contains(r, x, y))
}

fn look(p: &Pointer, r: Rect) -> (bool, bool) {
    let s = on(p, r);
    (s.hovered, s.pressed)
}

#[test]
fn an_unseen_pointer_hovers_nothing() {
    let p = Pointer::new();
    assert_eq!(look(&p, A), (false, false));
    assert_eq!(p.position(), None);
}

#[test]
fn hover_follows_the_pointer() {
    let mut p = Pointer::new();
    p.moved(20, 15);
    assert_eq!((look(&p, A), look(&p, B)), ((true, false), (false, false)));
    p.moved(70, 15);
    assert_eq!((look(&p, A), look(&p, B)), ((false, false), (true, false)));
}

#[test]
fn a_press_counts_only_on_the_widget_it_began_on() {
    let mut p = Pointer::new();
    p.pressed(20, 15);
    assert_eq!(look(&p, A), (true, true));
    p.moved(70, 15);
    assert_eq!((look(&p, A), look(&p, B)), ((false, false), (true, false)));
    p.moved(25, 15);
    assert_eq!(look(&p, A), (true, true));
    p.released();
    assert_eq!(look(&p, A), (true, false));
}

#[test]
fn a_touch_presses_without_hovering_and_leaves_nothing_behind() {
    let mut p = Pointer::new();
    p.touched(20, 15);
    assert_eq!(look(&p, A), (false, true));
    p.released();
    assert_eq!(look(&p, A), (false, false));
    assert_eq!(p.position(), None);
}

#[test]
fn leaving_the_window_clears_hover_and_press() {
    let mut p = Pointer::new();
    p.pressed(20, 15);
    p.left();
    assert_eq!(look(&p, A), (false, false));
}
