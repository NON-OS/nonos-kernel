// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FontWeight {
    Light = 0,
    #[default]
    Regular = 1,
    Medium = 2,
    Semibold = 3,
    Bold = 4,
}

impl FontWeight {
    pub const fn render_offset(self) -> i32 {
        match self {
            Self::Light => 0,
            Self::Regular => 0,
            Self::Medium => 1,
            Self::Semibold => 1,
            Self::Bold => 1,
        }
    }

    pub const fn alpha_boost(self) -> u8 {
        match self {
            Self::Light => 0,
            Self::Regular => 0,
            Self::Medium => 20,
            Self::Semibold => 35,
            Self::Bold => 50,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct TextStyle {
    pub size: u32,
    pub weight: FontWeight,
    pub color: u32,
    pub line_height: u32,
}

impl TextStyle {
    pub const fn new(size: u32, weight: FontWeight, color: u32) -> Self {
        Self { size, weight, color, line_height: 20 }
    }

    pub const fn with_line_height(mut self, lh: u32) -> Self {
        self.line_height = lh;
        self
    }
}
