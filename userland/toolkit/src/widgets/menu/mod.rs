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

//! A menu: a raised panel of rows, each an `Item` with an optional shortcut
//! and tick, with separators between groups. It draws inside the app's own
//! window over what is already painted. `place` picks the rect below an
//! anchor, inside the bounds it may use, and the app closes the menu when a
//! press lands outside that rect. The app keeps the highlighted row, moves
//! it with `next` for the arrow keys, and passes it as `hovered`.

mod build;
mod geometry;
mod item;
mod measure;
mod next;
mod paint;
mod place;
mod row;

pub use build::Menu;
pub use item::Item;
