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

//! A dialog: a panel over a scrim, with a title, a wrapped body, an optional
//! note in a tone and a row of buttons. Each button is a real `Button`, so it
//! presses and focuses like any other. The app keeps the focused button,
//! moves it with `next_focus` for Tab and Shift-Tab, and closes the dialog
//! when a press lands outside `panel`.

mod build;
mod geometry;
mod keys;
mod lines;
mod lit;
mod measure;
mod paint;
mod row;

pub use build::Dialog;
