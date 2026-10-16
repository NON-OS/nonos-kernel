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

//! The shared widgets. An app imports what it needs from here; a new widget is
//! a file in this folder and its two lines below. See
//! docs/userland/design-system/widgets.md.

pub mod button;
pub mod card;
pub mod draw;
pub mod ink;
pub mod label;
pub mod rect;
pub mod row;
pub mod section_header;
pub mod separator;
pub mod slider;
pub mod state;
pub mod switch;
pub mod text;

pub use crate::decorations::Rect;
pub use button::{Button, Kind};
pub use card::Card;
pub use ink::{Ink, Tone};
pub use label::{Align, Label};
pub use row::Row;
pub use section_header::SectionHeader;
pub use separator::Separator;
pub use slider::Slider;
pub use state::State;
pub use switch::Switch;
