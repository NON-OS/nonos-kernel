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

//! Muting text as far as the scheme allows, and no further.

use super::contrast::{BODY, LARGE};
use super::legible_walk::walk;

/// How far a secondary label steps towards the ground when the scheme has the
/// contrast to spare. A third of the way: far enough to read as secondary at a
/// glance. Where that would fail the floor, `muted` steps back towards the text.
pub const MUTED_TARGET: u8 = 86;

/// And the quietest text, half way down.
pub const QUIET_TARGET: u8 = 128;

/// How far a value beside its label, `text_2`, steps towards the ground.
pub const VALUE_TARGET: u8 = 36;

/// How far `accent_text` steps from the text towards the accent: where the
/// scheme can take it, the same colour as `mix(accent, text, 146)`.
pub const ACCENT_TEXT_TARGET: u8 = 109;

/// Secondary labels, captions, anything scanned past. Holds the body text floor
/// against both backgrounds.
pub fn muted(text: u32, bg: u32, surface: u32, target: u8) -> u32 {
    walk(text, bg, surface, target, BODY)
}

/// Hint text in an empty field, meant to be found rather than read. Held to the
/// 3:1 floor, which is what WCAG asks of text not carrying the content.
pub fn quiet(text: u32, bg: u32, surface: u32, target: u8) -> u32 {
    walk(text, bg, surface, target, LARGE)
}
