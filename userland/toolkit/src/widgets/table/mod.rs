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

//! A table: a header of column titles over striped rows of cells. Each `Col`
//! is fixed or takes a share of what the fixed ones leave, so the columns
//! fill the width given. The table draws only the rows it is given: a long
//! list passes the slice on screen and, with `first`, where that slice
//! starts, so the app scrolls by whole rows under a header that stays put.
//! `hit` names a header, for sorting, or a row and column, as a `Cell`.

mod build;
mod col;
mod geometry;
mod head;
mod hit;
mod lit;
mod measure;
mod paint;
mod put;
mod widths;

pub use build::Table;
pub use col::Col;
pub use hit::Cell;
