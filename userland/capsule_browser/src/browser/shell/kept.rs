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

use alloc::string::String;

/// A named tab group. `id` is stable for the group's life, so a tab keeps
/// its group across renames; `color` picks its tile tint.
#[derive(Clone)]
pub struct Group {
    pub id: u8,
    pub name: String,
    pub color: u8,
}

/// How the reader sets an article: theme (Light, Sepia, Dark), text size
/// step, column width (Narrow, Standard, Wide), and whether the reading
/// time shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderPrefs {
    pub theme: u8,
    pub size: u8,
    pub width: u8,
    pub show_time: bool,
}

pub const MAX_SIZE: u8 = 4;

impl Default for ReaderPrefs {
    fn default() -> Self {
        ReaderPrefs { theme: 0, size: 1, width: 1, show_time: true }
    }
}

impl ReaderPrefs {
    /// These settings held to the choices the reader offers, for a record
    /// another build or a damaged file may have written.
    pub fn clamped(self) -> ReaderPrefs {
        ReaderPrefs {
            theme: self.theme.min(2),
            size: self.size.min(MAX_SIZE),
            width: self.width.min(2),
            show_time: self.show_time,
        }
    }
}
