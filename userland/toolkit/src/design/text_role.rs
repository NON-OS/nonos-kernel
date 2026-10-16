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

//! The three text sizes the interface draws with.

/// What a run of text is for, which decides its size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextRole {
    /// Ordinary text. Its size equals `MIN_UI_PX`.
    Body,
    /// The title of a page or card.
    Title,
    /// The largest heading on a screen.
    Headline,
}

impl TextRole {
    /// The size in logical pixels before `readable_px` floors it and the
    /// text-size setting scales it (see `font/ttf/readable.rs`).
    pub const fn px(self) -> f32 {
        match self {
            TextRole::Body => 17.0,
            TextRole::Title => 21.0,
            TextRole::Headline => 26.0,
        }
    }
}
