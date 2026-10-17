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

//! What the pointer is over: the thing a click there acts on, named so the
//! window can tell a move inside one target from a move to the next.

/// What lies under the pointer. A card is named by its place in the visible
/// list, the scroll included, so a wheel that brings another card under a
/// still pointer is a new target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Target {
    #[default]
    None,
    /// A source tab, by its index in `TABS`.
    Tab(usize),
    /// A card, anywhere on it but its buttons.
    Card(usize),
    /// That card's install action.
    Action(usize),
    /// That card's Remove button, which only an installed card shows.
    Remove(usize),
}

impl Target {
    /// Whether this is the card at `at`, its body or one of its buttons.
    pub fn on_card(self, at: usize) -> bool {
        matches!(self, Target::Card(i) | Target::Action(i) | Target::Remove(i) if i == at)
    }
}
