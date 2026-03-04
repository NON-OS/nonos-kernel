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

pub const BG_WIDTH: u32 = 1280;
pub const BG_HEIGHT: u32 = 800;

const BG_COUNT: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Background {
    Default = 0,
    DeepBlue = 1,
    Twilight = 2,
    Forest = 3,
    Sunset = 4,
    Midnight = 5,
    Ocean = 6,
    CyberGrid = 7,
}

impl Background {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Default,
            1 => Self::DeepBlue,
            2 => Self::Twilight,
            3 => Self::Forest,
            4 => Self::Sunset,
            5 => Self::Midnight,
            6 => Self::Ocean,
            7 => Self::CyberGrid,
            _ => Self::Default,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Default => "Dark Gradient",
            Self::DeepBlue => "Deep Blue",
            Self::Twilight => "Twilight",
            Self::Forest => "Forest",
            Self::Sunset => "Sunset",
            Self::Midnight => "Midnight",
            Self::Ocean => "Ocean",
            Self::CyberGrid => "Cyber Grid",
        }
    }

    pub(crate) fn gradient_colors(&self) -> (u32, u32) {
        match self {
            Self::Default => (0xFF0D1117, 0xFF1A1F27),
            Self::DeepBlue => (0xFF0A1628, 0xFF1E3A5F),
            Self::Twilight => (0xFF1A0A28, 0xFF3D1F5F),
            Self::Forest => (0xFF0A1A0F, 0xFF1F3D28),
            Self::Sunset => (0xFF1A0F0A, 0xFF5F3D1F),
            Self::Midnight => (0xFF050508, 0xFF0A0A10),
            Self::Ocean => (0xFF0A1A1F, 0xFF1F4D5F),
            Self::CyberGrid => (0xFF0A0A14, 0xFF14142A),
        }
    }

    pub(crate) fn has_pattern(&self) -> bool {
        matches!(self, Self::CyberGrid)
    }

    pub(crate) fn pixels(&self) -> Option<&'static [u32]> {
        None
    }

    pub(crate) fn count() -> u8 {
        BG_COUNT
    }

    pub(crate) fn next(&self) -> Self {
        let next = (*self as u8 + 1) % BG_COUNT;
        Self::from_u8(next)
    }

    pub(crate) fn prev(&self) -> Self {
        let prev = if *self as u8 == 0 { BG_COUNT - 1 } else { *self as u8 - 1 };
        Self::from_u8(prev)
    }
}
