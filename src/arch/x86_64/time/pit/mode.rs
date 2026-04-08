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

use super::command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Mode {
    InterruptOnTerminal = 0,
    HardwareOneShot = 1,
    #[default]
    RateGenerator = 2,
    SquareWave = 3,
    SoftwareStrobe = 4,
    HardwareStrobe = 5,
}

impl Mode {
    pub const fn bits(&self) -> u8 {
        match self {
            Self::InterruptOnTerminal => command::MODE_0,
            Self::HardwareOneShot => command::MODE_1,
            Self::RateGenerator => command::MODE_2,
            Self::SquareWave => command::MODE_3,
            Self::SoftwareStrobe => command::MODE_4,
            Self::HardwareStrobe => command::MODE_5,
        }
    }

    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::InterruptOnTerminal),
            1 => Some(Self::HardwareOneShot),
            2 => Some(Self::RateGenerator),
            3 => Some(Self::SquareWave),
            4 => Some(Self::SoftwareStrobe),
            5 => Some(Self::HardwareStrobe),
            _ => None,
        }
    }

    pub const fn is_periodic(&self) -> bool {
        matches!(self, Self::RateGenerator | Self::SquareWave)
    }

    pub const fn is_oneshot(&self) -> bool {
        matches!(self, Self::InterruptOnTerminal | Self::HardwareOneShot | Self::SoftwareStrobe | Self::HardwareStrobe)
    }
}
