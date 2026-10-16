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

//! How much of each see-through shell colour covers what is behind it, out of
//! 255. The glass surfaces start here and are made more opaque where a scheme
//! needs it for its text to read (`glass`).

/// A menu's panel.
pub const PANEL: u8 = 0xE6;
/// The top bar.
pub const BAR: u8 = 0xE0;
/// The dock.
pub const DOCK: u8 = 0xB8;
/// The hairline round a panel, a menu and the dock.
pub const LINE: u8 = 0x29;
/// The hairline round a tile.
pub const LINE_SOFT: u8 = 0x17;
/// The hairline round the focused or pulsing dock tile.
pub const LINE_HARD: u8 = 0x57;
/// An open menu-bar title, and a running app's dot in the dock.
pub const ACCENT_DIM: u8 = 0x21;
/// The menu row under the pointer.
pub const ACCENT_HOVER: u8 = 0x38;
/// The pill behind a desktop entry being renamed.
pub const PILL_EDIT: u8 = 0xF2;
/// The backing behind a desktop entry, so its name reads on any wallpaper.
pub const ICON_SCRIM: u8 = 0x8C;
/// The dock tile of the focused app.
pub const TILE_ACTIVE: u8 = 0x2E;
/// The dock tile of an app that is starting.
pub const TILE_PULSE: u8 = 0x2E;
/// The dock tile of an app with a window open.
pub const TILE_OPEN: u8 = 0x1A;
/// Any other tile.
pub const TILE_FILL: u8 = 0x12;
/// The tile of an app turned off at first-boot setup.
pub const TILE_OFF: u8 = 0x18;
