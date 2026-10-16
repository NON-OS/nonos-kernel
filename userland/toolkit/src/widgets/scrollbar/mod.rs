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

//! A vertical scroll bar: a rounded thumb whose length is the share of the
//! content in view and whose place is how far it is scrolled. No track is
//! drawn. When the content fits, nothing is drawn and nothing is hit. The
//! hit test turns a pointer y into an offset for click and drag.

mod build;
mod geometry;
mod paint;

pub use build::Scrollbar;
