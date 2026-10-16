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

//! The four kinds of button.

/// How much weight a button carries, which decides its colours.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Kind {
    /// A raised body with a strong outline: the ordinary button.
    #[default]
    Secondary,
    /// An accent body: the one action a screen leads with, or the choice in
    /// force.
    Primary,
    /// No body, accent label: a quiet action.
    Plain,
    /// A danger outline and label: an action that removes something. With
    /// `State::selected` it is armed and fills with `danger`.
    Danger,
}
