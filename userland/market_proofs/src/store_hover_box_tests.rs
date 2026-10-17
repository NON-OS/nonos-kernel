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

//! A card's buttons are targets of their own, the input router's leave names
//! nothing, and the hover moves nothing: what every point of the window names
//! is the same whatever is hovered.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};

use crate::store::progress::Progress;
use crate::store::state::State;
use crate::store::ui::geometry::{action_rect, list_w, remove_rect, row_top};
use crate::store::ui::hover::{hover_to, target_at};
use crate::store::ui::metrics::{PAD_X, WIN_H, WIN_W};
use crate::store::ui::target::Target;
use crate::store_hover_tests::{at, window};

#[test]
fn the_input_routers_leave_lands_on_nothing() {
    assert!(target_at(&window(0), -1, -1) == Target::None);
    assert!(target_at(&window(0), -30, -45) == Target::None);
}

/// What every seventh point of the window names.
fn map(state: &State) -> Vec<Target> {
    (0..WIN_H)
        .step_by(7)
        .flat_map(|y| (0..WIN_W).step_by(7).map(move |x| (x, y)))
        .map(|(x, y)| at(state, x, y))
        .collect()
}

#[test]
fn hover_never_moves_a_box() {
    let mut state = window(2);
    let before = map(&state);
    for t in [Target::None, Target::Tab(1), Target::Card(4), Target::Action(5), Target::Remove(3)] {
        assert!(before.contains(&t), "{t:?}");
        state.hover = t;
        assert!(map(&state) == before, "{t:?}");
    }
}

#[test]
fn a_button_is_its_own_target_and_remove_only_on_an_installed_card() {
    let (state, w) = (window(0), list_w(WIN_W));
    for slot in 0..state.rows {
        let (top, mut hover) = (row_top(slot), Target::Card(slot));
        let (ax, ay, aw, ah) = action_rect(PAD_X, top, w);
        assert!(hover_to(&mut hover, at(&state, ax, ay)) == Repaint);
        assert!(hover == Target::Action(slot));
        assert!(hover_to(&mut hover, at(&state, ax + aw - 1, ay + ah - 1)) == Idle);
        let (rx, ry, rw, rh) = remove_rect(PAD_X, top, w);
        let installed = state.listings[slot].progress == Progress::Installed;
        let remove = if installed { Target::Remove(slot) } else { Target::Card(slot) };
        assert!(at(&state, rx, ry) == remove && at(&state, rx + rw - 1, ry + rh - 1) == remove);
    }
}
