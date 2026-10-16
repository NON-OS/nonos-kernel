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

//! The shell's colours, worked out from the theme's roles so a theme chosen in
//! Settings restyles the top bar, the dock, the menus and the prompts.

mod alpha;
mod from_roles;
mod glass;
mod prompt;
mod radius;
mod table;

pub use from_roles::current;
pub use radius::{R_CARD, R_DOCK, R_TILE};
pub use table::ShellPalette;
