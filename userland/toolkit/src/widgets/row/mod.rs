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

//! A list row: a label with an optional muted note on the left, and an
//! optional value, room for an app's own control and a disclosure chevron on
//! the right. A row fills the width it is given and draws no hairline;
//! separators are the `Separator` widget's job.

mod build;
mod chevron;
mod geometry;
mod lanes;
mod measure;
mod options;
mod paint;

pub use build::Row;
