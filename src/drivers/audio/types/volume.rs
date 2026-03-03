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

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Volume(u8);

impl Volume {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(100);
    pub const DEFAULT: Self = Self(80);

    #[inline]
    pub const fn new(percent: u8) -> Self {
        if percent > 100 {
            Self(100)
        } else {
            Self(percent)
        }
    }

    #[inline]
    pub const fn percent(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn to_gain(&self) -> u8 {
        ((self.0 as u16 * 127) / 100) as u8
    }

    #[inline]
    pub const fn from_gain(gain: u8) -> Self {
        let percent = ((gain as u16 * 100) / 127) as u8;
        Self::new(percent)
    }

    #[inline]
    pub const fn is_muted(&self) -> bool {
        self.0 == 0
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}
