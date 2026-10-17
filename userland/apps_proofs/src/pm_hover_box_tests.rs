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

//! The input router's leave names nothing, and the hover moves nothing: what
//! every point of the window names is the same whatever is hovered.

use crate::metrics::{WIN_H, WIN_W};
use crate::pm::state::{State, SCREENS};
use crate::pm::ui::hit::Target;
use crate::pm::ui::hover::target_at;
use crate::pm_hover_tests::{at, window};

#[test]
fn the_input_routers_leave_lands_on_nothing() {
    for s in SCREENS {
        let state = window(s, 0);
        assert!(target_at(&state, -1, -1).is_none() && target_at(&state, -30, -45).is_none());
    }
}

/// What every twelfth point of the window names.
fn map(state: &State) -> Vec<Option<Target>> {
    let points = (0..WIN_H).step_by(12).flat_map(|y| (0..WIN_W).step_by(12).map(move |x| (x, y)));
    points.map(|(x, y)| at(state, x, y)).collect()
}

#[test]
fn hover_never_moves_a_box() {
    for s in SCREENS {
        let mut state = window(s, 2);
        let before = map(&state);
        let mut seen = Vec::new();
        for t in &before {
            if !seen.contains(t) {
                seen.push(*t);
            }
        }
        assert!(seen.len() > SCREENS.len());
        for t in seen {
            state.hover = t;
            assert!(map(&state) == before);
        }
    }
}
