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

//! About's sidebar: a click names the entry drawn under it, and a move inside
//! one entry asks for no repaint while a move onto the next asks for one. The
//! pointer the hover proofs feed is set up here.

use nonos_app_skeleton::EventOutcome::{self, Idle, Repaint};
use nonos_app_skeleton::InputEvent;
use nonos_app_skeleton::InputKind::{self, PointerAbs};
use nonos_toolkit::widgets::{Pointer, State as Look};

use crate::about::section::{Section, SECTIONS};
use crate::about::ui::hover::{look, on_pointer};
use crate::about::ui::{hit, nav_geom::rect};

/// A pointer and the entry it names, as About's state holds them.
pub(crate) struct Rail(pub(crate) Pointer, pub(crate) Option<Section>);

impl Rail {
    pub(crate) fn feed(&mut self, kind: InputKind, (x, y): (i32, i32)) -> Option<EventOutcome> {
        let (flags, code, delta_x, delta_y, timestamp_ns) = (0, 0, 0, 0, 0);
        let e = InputEvent { kind, flags, code, x, y, delta_x, delta_y, timestamp_ns };
        on_pointer(&mut self.0, &mut self.1, &e)
    }

    pub(crate) fn look(&self, i: usize) -> Look {
        look(&self.0, self.1, SECTIONS[i])
    }
}

/// The corners and then the centre of entry `i`'s drawn box.
pub(crate) fn points(i: usize) -> [(i32, i32); 5] {
    let r = rect(i);
    let (x0, y0) = (r.x as i32, r.y as i32);
    let (x1, y1) = (x0 + r.w as i32 - 1, y0 + r.h as i32 - 1);
    [(x0, y0), (x1, y0), (x0, y1), (x1, y1), ((x0 + x1) / 2, (y0 + y1) / 2)]
}

#[test]
fn a_click_anywhere_on_an_entry_names_the_entry_drawn_there_and_between_names_none() {
    for (i, s) in SECTIONS.iter().enumerate() {
        assert!(points(i).iter().all(|&(x, y)| hit::at(x, y) == Some(*s)), "entry {i}");
        let r = rect(i);
        assert!(hit::at(r.x as i32, (r.y + r.h) as i32).is_none(), "below entry {i}");
    }
}

#[test]
fn a_move_inside_an_entry_repaints_nothing_and_one_onto_the_next_repaints() {
    let mut rail = Rail(Pointer::new(), None);
    for i in 0..SECTIONS.len() - 1 {
        rail.feed(PointerAbs, points(i)[0]);
        assert!(rail.1 == Some(SECTIONS[i]));
        assert!(rail.feed(PointerAbs, points(i)[4]) == Some(Idle));
        assert!(rail.feed(PointerAbs, points(i + 1)[0]) == Some(Repaint));
        assert!(rail.1 == Some(SECTIONS[i + 1]) && rail.look(i + 1).hovered);
    }
}
