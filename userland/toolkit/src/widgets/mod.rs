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
pub mod checkbox;
pub mod column;
pub mod draw;
pub mod field;
pub mod icon_button;
pub mod ink;
pub mod label;
mod marked;
pub mod nav_item;
pub mod pill;
pub mod pointer;
pub mod progress;
pub mod radio;
pub mod rect;
pub mod row;
pub mod scrollbar;
pub mod scrolled;
pub mod section_header;
pub mod separator;
pub mod slider;
pub mod state;
pub mod surface;
pub mod switch;
pub mod tabs;
pub mod text;

pub use crate::decorations::Rect;
pub use button::{Button, Kind};
pub use card::Card;
pub use checkbox::Checkbox;
pub use column::Column;
pub use field::Field;
pub use icon_button::IconButton;
pub use ink::{Ink, Tone};
pub use label::{Align, Label};
pub use nav_item::NavItem;
pub use pill::Pill;
pub use pointer::Pointer;
pub use progress::Progress;
pub use radio::Radio;
pub use row::Row;
pub use scrollbar::Scrollbar;
pub use scrolled::Scrolled;
pub use section_header::SectionHeader;
pub use separator::Separator;
pub use slider::Slider;
pub use state::State;
pub use surface::Surface;
pub use switch::Switch;
pub use tabs::Tabs;
