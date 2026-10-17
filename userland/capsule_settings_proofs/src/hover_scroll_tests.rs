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

//! What the pointer hovers in Settings, off the rows and under the scroll:
//! a move from a row onto empty space asks for a repaint, the scroll shifts
//! the pointer as it shifts a click, and the hover moves no row.

use nonos_app_skeleton::EventOutcome::Repaint;

use crate::hover_tests::{at, page, rows, LABEL_X, VIEW_H};
use crate::settings::section::{Section, SECTIONS};
use crate::settings::ui::hover::{hover_to, target_at};
use crate::settings::ui::metrics::PANE_PAD_TOP;
use crate::settings::ui::target::Target;
use crate::settings::ui::walk::content_h;

#[test]
fn a_move_off_a_row_onto_empty_space_repaints() {
    let state = page(Section::General);
    let (y, _, row) = rows(&state)[0];
    for empty in [PANE_PAD_TOP + 1, y - 1, content_h(&state) + 1] {
        let mut hover = row;
        assert!(at(&state, empty) == Target::None);
        assert!(hover_to(&mut hover, at(&state, empty)) == Repaint && hover == Target::None);
    }
}

#[test]
fn the_pointer_is_shifted_by_the_scroll_as_a_click_is() {
    for s in SECTIONS {
        let still = page(s);
        let mut scrolled = page(s);
        scrolled.scroll_px[s.index()] = 37;
        for y in 0..content_h(&still) - 37 {
            let under = target_at(&scrolled, LABEL_X, y as i32, VIEW_H, None);
            assert!(under == at(&still, y + 37));
        }
    }
}

#[test]
fn hover_never_moves_a_row() {
    for s in SECTIONS {
        let mut state = page(s);
        let before = rows(&state);
        for (_, _, t) in before.clone() {
            state.hover = t;
            assert!(rows(&state) == before);
        }
    }
}
