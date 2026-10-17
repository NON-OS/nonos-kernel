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

//! Names the target under a point by the tests a click makes, so a click acts
//! on what the pointer lit and a move repaints only on crossing to another.

use nonos_app_skeleton::EventOutcome;

use crate::pm::state::State;

use super::hit::{self, Target};

/// The target at `(x, y)` in content coordinates, on the frame last painted,
/// the scroll included. The input router's leave arrives left of and above
/// the content, where nothing is.
pub fn target_at(state: &State, x: i32, y: i32) -> Option<Target> {
    if x < 0 || y < 0 {
        return None;
    }
    hit::at(state, state.fb_w, state.fb_h, x, y)
}

/// Moves the hover to `next`, asking for a repaint only when it changed.
pub fn hover_to(hover: &mut Option<Target>, next: Option<Target>) -> EventOutcome {
    if core::mem::replace(hover, next) == next {
        EventOutcome::Idle
    } else {
        EventOutcome::Repaint
    }
}
