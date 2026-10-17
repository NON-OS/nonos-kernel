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

//! What the pointer hovers in Settings: a move inside one row asks for no
//! repaint, and a move to the next row asks for one.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};

use crate::settings::section::{Section, SECTIONS, SECTION_COUNT};
use crate::settings::state::{State, Wifi};
use crate::settings::ui::hover::{hover_to, target_at};
use crate::settings::ui::metrics::{PANE_PAD_X, SIDEBAR_W};
use crate::settings::ui::target::Target;
use crate::settings::ui::walk::{walk, Item};

pub(crate) const VIEW_H: u32 = 100_000;
pub(crate) const LABEL_X: i32 = (SIDEBAR_W + PANE_PAD_X) as i32 + 20;

pub(crate) fn page(section: Section) -> State {
    let wifi = Wifi { saved_count: 0 };
    let scroll_px = [0; SECTION_COUNT];
    let hover = Target::None;
    State { section, scroll_px, search_scroll: 0, win_w: 900, wifi_network_count: 0, wifi, hover }
}

pub(crate) fn at(state: &State, y: u32) -> Target {
    target_at(state, LABEL_X, y as i32, VIEW_H, None)
}

/// Every row's top and height on the page, with what its label's middle names.
pub(crate) fn rows(state: &State) -> Vec<(u32, u32, Target)> {
    let mut out = Vec::new();
    walk(state, |y, h, item| {
        if matches!(item, Item::Row(..) | Item::Wallpaper(_) | Item::Network(_)) {
            out.push((y, h, at(state, y + h / 2)));
        }
    });
    out
}

#[test]
fn a_move_inside_a_row_repaints_nothing_and_one_to_the_next_repaints() {
    let mut pairs = 0;
    for s in SECTIONS {
        let state = page(s);
        let editable: Vec<_> = rows(&state).into_iter().filter(|r| r.2 != Target::None).collect();
        for w in editable.windows(2) {
            let ((y, h, here), (next_y, _, next)) = (w[0], w[1]);
            let mut hover = here;
            assert!(at(&state, y) == here && at(&state, y + h - 1) == here);
            assert!(hover_to(&mut hover, at(&state, y + h - 1)) == Idle);
            assert!(hover_to(&mut hover, at(&state, next_y)) == Repaint && hover == next);
            pairs += 1;
        }
    }
    assert!(pairs > 0);
}
