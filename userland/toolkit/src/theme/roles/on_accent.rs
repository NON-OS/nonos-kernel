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

//! The ink for text and icons drawn on the accent.

use super::super::contrast::at_least;

/// The first of the ground, the text, black and white that reads on the accent at
/// body-text contrast, or white if none of them does.
pub(super) fn on_accent(accent: u32, bg: u32, text: u32) -> u32 {
    [bg, text, 0xFF00_0000, 0xFFFF_FFFF]
        .into_iter()
        .find(|&ink| at_least(ink, accent, 45))
        .unwrap_or(0xFFFF_FFFF)
}
