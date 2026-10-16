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

//! The light scheme. Kept apart from `house.rs` because that file describes
//! schemes with a dark, colour-cast ground.

use super::Scheme;

/// A light ground with dark text, for daylight or for anyone who reads better that way.
pub const LIGHT: Scheme = Scheme {
    bg: 0xFFF4_F7FC,
    surface: 0xFFFF_FFFF,
    accent: 0xFF25_63EB,
    text: 0xFF13_213A,
    border: 0xFFD9_E2EF,
};
