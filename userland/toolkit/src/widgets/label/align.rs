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

//! Where a label sits across its box.

/// Where a label sits across its box.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum Align {
    /// Against the left edge.
    #[default]
    Left,
    /// In the middle.
    Centre,
    /// Against the right edge.
    Right,
}
