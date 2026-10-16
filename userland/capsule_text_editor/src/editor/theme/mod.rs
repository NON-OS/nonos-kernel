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

//! The editor palette. A theme carries every colour the shell paints with, so
//! switching themes recolours the whole editor at once: body, gutter, syntax,
//! and the chrome (tab bar, sidebar, activity bar, status bar). The choices are
//! System, which follows the OS theme set in Settings and is the default, then
//! four fixed themes. One is active process-wide, so every tab shares it and the
//! theme button can switch it from any paint path.

mod active;
mod fields;
mod ink;
mod named;
mod system;

pub use active::{active, cycle};
pub use fields::Theme;
pub use system::SELECT_WASH;
