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

//! Names the target under the pointer by the tests a click makes, so a move
//! asks for a repaint only when it crosses from one target to another.

use nonos_app_skeleton::EventOutcome;

use crate::settings::state::State;

use super::hit::{at, Hit};
use super::metrics::SIDEBAR_W;
use super::nav_geom;
use super::results_geom::index_at;
use super::target::Target;

/// The target at `(x, y)` in content coordinates, in the click path's own
/// order: the sidebar, then the pane above `view_h`, its y shifted by the
/// scroll. `found` is the result count while a search is on screen.
pub fn target_at(state: &State, x: i32, y: i32, view_h: u32, found: Option<usize>) -> Target {
    if x < 0 || y < 0 {
        return Target::None;
    }
    if x < SIDEBAR_W as i32 {
        return nav_geom::at(x, y).map_or(Target::None, Target::Nav);
    }
    if y >= view_h as i32 {
        return Target::None;
    }
    if let Some(n) = found {
        return index_at(y, state.search_scroll, n).map_or(Target::None, Target::Result);
    }
    let pane_w = state.win_w.saturating_sub(SIDEBAR_W);
    let scroll = state.scroll_px[state.section.index()];
    match at(state, x - SIDEBAR_W as i32, y, scroll, pane_w) {
        Hit::Field { index, control: false } => Target::Row(index),
        Hit::Field { index, control: true } => Target::Control(index),
        Hit::Network(i) => Target::Network(i),
        Hit::Scan => Target::Scan,
        Hit::None => Target::None,
    }
}

/// Moves the hover to `next`, asking for a repaint only when it changed.
pub fn hover_to(hover: &mut Target, next: Target) -> EventOutcome {
    if core::mem::replace(hover, next) == next {
        EventOutcome::Idle
    } else {
        EventOutcome::Repaint
    }
}
