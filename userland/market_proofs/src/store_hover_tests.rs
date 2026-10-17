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

//! What the pointer hovers in the marketplace window: a move inside one card
//! or tab asks for no repaint and a move to the next asks for one, and the
//! scroll shifts the pointer as it shifts a click.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};

use crate::store::listing::Listing;
use crate::store::progress::Progress;
use crate::store::state::State;
use crate::store::tab::TABS;
use crate::store::ui::geometry::{list_w, row_top};
use crate::store::ui::hover::{hover_to, target_at};
use crate::store::ui::metrics::{CARD_H, PAD_X, WIN_W};
use crate::store::ui::target::Target;
use crate::store_tab_strip_tests::hit;

/// Twelve listings, every third installed, eight to a window, at `scroll`.
pub(crate) fn window(scroll: usize) -> State {
    let one = |i: usize| {
        let mut l =
            Listing::new(format!("nonos.app{i}").into_bytes(), [0; 32], b"a".to_vec(), true);
        l.progress = if i % 3 == 0 { Progress::Installed } else { Progress::Idle };
        l
    };
    let listings = (0..12).map(one).collect();
    State { listings, scroll, rows: 8, fb_w: WIN_W, hover: Target::None }
}

pub(crate) fn at(state: &State, x: u32, y: u32) -> Target {
    target_at(state, x as i32, y as i32)
}

#[test]
fn a_move_inside_a_card_repaints_nothing_and_one_to_the_next_repaints() {
    let w = list_w(WIN_W);
    for scroll in [0, 3] {
        let state = window(scroll);
        for slot in 0..state.rows - 1 {
            let (top, card) = (row_top(slot), Target::Card(scroll + slot));
            let mut hover = card;
            assert!(at(&state, PAD_X, top) == card);
            assert!(hover_to(&mut hover, at(&state, PAD_X + w - 1, top + CARD_H - 1)) == Idle);
            assert!(hover_to(&mut hover, at(&state, PAD_X, row_top(slot + 1))) == Repaint);
            assert!(hover == Target::Card(scroll + slot + 1));
        }
    }
}

#[test]
fn a_move_inside_a_tab_repaints_nothing_and_one_to_the_next_repaints() {
    let state = window(0);
    for i in 0..TABS.len() - 1 {
        let ((x0, x1, y0, y1), next) = (hit(i), hit(i + 1));
        let mut hover = at(&state, x0, y0);
        assert!(hover == Target::Tab(i) && hover_to(&mut hover, at(&state, x1, y1)) == Idle);
        assert!(hover_to(&mut hover, at(&state, next.0, next.2)) == Repaint);
        assert!(hover == Target::Tab(i + 1));
    }
}
