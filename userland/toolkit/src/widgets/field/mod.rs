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

//! A one-line text or search field: a rounded body holding an optional quiet
//! icon, the text, or a quiet placeholder while it is empty, and a caret while
//! it has the keyboard.
//! The accent edge a focused field draws is its focus mark, so it takes no
//! separate `focus_ring`. `pressed` and `selected` mean nothing to a field
//! and are ignored.

mod build;
mod geometry;
mod look;
mod paint;
mod shown;

pub use build::Field;
