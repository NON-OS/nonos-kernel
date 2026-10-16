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

//! The table of the shell's colours, one field per colour it paints with.

use super::prompt::Prompt;

/// Every colour the shell paints its chrome with, as packed ARGB. The glass
/// grounds, the lines, the washes and the tiles are see-through and must be
/// drawn through a blending call; the inks and `prompt` are opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellPalette {
    /// A menu's panel; see-through.
    pub panel: u32,
    /// The top bar; see-through.
    pub bar: u32,
    /// The dock; see-through.
    pub dock: u32,
    /// The hairline round a panel, a menu and the dock.
    pub line: u32,
    /// The hairline round a tile or the search field.
    pub line_soft: u32,
    /// The hairline round the focused or pulsing dock tile.
    pub line_hard: u32,
    /// Icons, the caret, the current page, a focused button's ring.
    pub accent: u32,
    /// An open menu-bar title, a running app's dot.
    pub accent_dim: u32,
    /// The menu row under the pointer.
    pub accent_hover: u32,
    /// Body text and titles.
    pub text: u32,
    /// Secondary text: menu-bar titles, the status line, Launchpad hints.
    pub text_dim: u32,
    /// Text for something unavailable, such as an app turned off.
    pub text_muted: u32,
    /// A row that destroys something.
    pub negative: u32,
    /// A battery with charge to spare.
    pub positive: u32,
    /// A battery running low.
    pub warn: u32,
    /// The pill behind a desktop entry being renamed.
    pub pill_edit: u32,
    /// The backing behind a desktop entry, so its name reads on any wallpaper.
    pub icon_scrim: u32,
    /// The dock tile of the focused app.
    pub tile_active: u32,
    /// The dock tile of an app that is starting.
    pub tile_pulse: u32,
    /// The dock tile of an app with a window open.
    pub tile_open: u32,
    /// Any other tile.
    pub tile_fill: u32,
    /// The tile of an app turned off at first-boot setup: grey, where the
    /// others are tinted.
    pub tile_off: u32,
    /// The Launchpad's full-screen wash; opaque, as it is painted with `fill_rect`.
    pub launchpad: u32,
    /// The centred prompts.
    pub prompt: Prompt,
}
