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

use crate::store::progress::Progress;
use crate::store::state::State;

use super::geometry::{list_top, list_w, on_action, on_remove, row_top, slot_at};
use super::metrics::{HEAD_H, PAD_TOP, PAD_X, TAB_H};
use super::tab_strip::tab_at;
use super::target::Target;

/// The target at `(x, y)` in content coordinates: a tab in the tab band,
/// else a card of the list or one of its buttons, the scroll included.
pub fn target_at(state: &State, x: i32, y: i32) -> Target {
    if x < 0 || y < 0 {
        return Target::None;
    }
    let top = (PAD_TOP + HEAD_H) as i32;
    if y >= top && y < top + TAB_H as i32 {
        return tab_at(state.fb_w, x, y).map_or(Target::None, Target::Tab);
    }
    card_at(state, x, y)
}

/// The card under the point, or its Remove or its action. Only an installed
/// card shows Remove, so only there is it a target.
fn card_at(state: &State, x: i32, y: i32) -> Target {
    let width = list_w(state.fb_w);
    if y < list_top() as i32 || x < PAD_X as i32 || x >= (PAD_X + width) as i32 {
        return Target::None;
    }
    let Some(slot) = slot_at(y, state.rows) else {
        return Target::None;
    };
    let at = state.scroll + slot;
    let shown = state.visible();
    let Some(listing) = shown.get(at).and_then(|&i| state.listings.get(i)) else {
        return Target::None;
    };
    let installed = listing.progress == Progress::Installed;
    if installed && on_remove(x, y, PAD_X, row_top(slot), width) {
        return Target::Remove(at);
    }
    if on_action(x, y, PAD_X, row_top(slot), width) {
        return Target::Action(at);
    }
    Target::Card(at)
}

/// Moves the hover to `next`, asking for a repaint only when it changed.
pub fn hover_to(hover: &mut Target, next: Target) -> EventOutcome {
    if core::mem::replace(hover, next) == next {
        EventOutcome::Idle
    } else {
        EventOutcome::Repaint
    }
}
