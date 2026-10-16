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

//! The corner radii the shell draws its tiles, cards and dock with, in logical
//! pixels.

/// A dock tile, a menu row's highlight, a desktop entry's backing.
pub const R_TILE: u32 = 8;
/// A menu's panel.
pub const R_CARD: u32 = 12;
/// The dock, and the Launchpad's search field.
pub const R_DOCK: u32 = 18;
