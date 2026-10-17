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

//! Clicking a card.

use nonos_app_skeleton::EventOutcome;

use super::state::State;
use super::ui::target::Target;

/// A click on the card at `at` in the visible list, or on one of its
/// buttons, as `target_at` named it.
pub fn on_list_click(state: &mut State, card: Target) -> EventOutcome {
    let (Target::Card(at) | Target::Action(at) | Target::Remove(at)) = card else {
        return EventOutcome::Idle;
    };
    let moved = state.select_slot(at - state.scroll);
    // The button does what Enter does: it reads Open once installed, and
    // offers nothing where no NONOS disk can hold the model.
    // Only an installed card shows Remove, so only there is it a click.
    if card == Target::Remove(at) {
        state.asked = Some(super::install::remove(state));
        return EventOutcome::Repaint;
    }
    if card == Target::Action(at) {
        state.asked = super::install_primary::primary(state);
        return EventOutcome::Repaint;
    }
    match moved {
        true => EventOutcome::Repaint,
        false => EventOutcome::Idle,
    }
}
