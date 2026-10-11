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

mod bookmarks;
mod cells;
mod downloads;
pub mod extent;
pub mod group_head;
mod group_pills;
mod header;
mod history;
mod paint;
mod pill_row;
pub mod pills;
mod rows;
pub mod tab_chip;
mod tab_grid;
mod tab_head;

pub use paint::paint;
