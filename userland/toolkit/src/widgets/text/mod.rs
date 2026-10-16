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

//! Text helpers for widgets: measuring, placing, fitting and wrapping
//! proportional runs, all cut on char boundaries and never sized by count.
//! `measure_ttf`, `text_ttf` and `line_height` each apply `readable_px`
//! themselves, so these helpers pass `px` through unchanged.

mod fit;
mod measure;
mod place;
mod tail;
mod wrap;

pub use fit::{truncate, truncate_by};
pub use measure::{centre_top, width};
pub use place::{centre, left, right};
pub use tail::{tail, tail_by};
pub use wrap::{wrap, wrap_by};
