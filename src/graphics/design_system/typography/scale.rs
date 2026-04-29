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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FontSize {
    Tiny = 10,
    Caption = 11,
    Callout = 12,
    Body = 13,
    Headline = 17,
    Title = 22,
    LargeTitle = 28,
    Display = 34,
}

impl FontSize {
    pub const fn scale_factor(self) -> u32 {
        match self {
            Self::Tiny | Self::Caption | Self::Callout | Self::Body => 1,
            Self::Headline | Self::Title => 2,
            Self::LargeTitle | Self::Display => 3,
        }
    }

    pub const fn line_height(self) -> u32 {
        match self {
            Self::Tiny => 14,
            Self::Caption => 16,
            Self::Callout => 18,
            Self::Body => 20,
            Self::Headline => 24,
            Self::Title => 28,
            Self::LargeTitle => 36,
            Self::Display => 44,
        }
    }

    pub const fn letter_spacing(self) -> i32 {
        match self {
            Self::Tiny | Self::Caption => 0,
            Self::Callout | Self::Body => 0,
            Self::Headline => -1,
            Self::Title => -1,
            Self::LargeTitle | Self::Display => -2,
        }
    }
}

pub const SCALE_NORMAL: u32 = 1;
pub const SCALE_LARGE: u32 = 2;
pub const SCALE_XLARGE: u32 = 3;
pub const SCALE_HUGE: u32 = 4;

pub const LINE_HEIGHT_TIGHT: u32 = 16;
pub const LINE_HEIGHT_NORMAL: u32 = 20;
pub const LINE_HEIGHT_RELAXED: u32 = 24;
pub const LINE_HEIGHT_LOOSE: u32 = 32;
