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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Theme {
    NonosDark = 0,
    GitHubDark = 1,
    SolarizedDark = 2,
    DeepPurple = 3,
    OceanBlue = 4,
    ForestGreen = 5,
}

impl Theme {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NonosDark,
            1 => Self::GitHubDark,
            2 => Self::SolarizedDark,
            3 => Self::DeepPurple,
            4 => Self::OceanBlue,
            5 => Self::ForestGreen,
            _ => Self::NonosDark,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::NonosDark => "NONOS Dark",
            Self::GitHubDark => "GitHub Dark",
            Self::SolarizedDark => "Solarized Dark",
            Self::DeepPurple => "Deep Purple",
            Self::OceanBlue => "Ocean Blue",
            Self::ForestGreen => "Forest Green",
        }
    }

    pub fn count() -> u8 {
        6
    }

    pub fn next(&self) -> Self {
        let next = (*self as u8 + 1) % Self::count();
        Self::from_u8(next)
    }

    pub fn prev(&self) -> Self {
        let prev = if *self as u8 == 0 {
            Self::count() - 1
        } else {
            *self as u8 - 1
        };
        Self::from_u8(prev)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ColorScheme {
    pub bg_primary: u32,
    pub bg_secondary: u32,
    pub bg_tertiary: u32,
    pub text_primary: u32,
    pub text_secondary: u32,
    pub accent: u32,
    pub success: u32,
    pub warning: u32,
    pub error: u32,
    pub border: u32,
}
