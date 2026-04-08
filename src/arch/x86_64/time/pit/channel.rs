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

use super::{ports, command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Channel0 = 0,
    Channel1 = 1,
    Channel2 = 2,
}

impl Channel {
    pub const fn data_port(&self) -> u16 {
        match self {
            Self::Channel0 => ports::CHANNEL0,
            Self::Channel1 => ports::CHANNEL1,
            Self::Channel2 => ports::CHANNEL2,
        }
    }

    pub const fn select_bits(&self) -> u8 {
        match self {
            Self::Channel0 => command::CHANNEL_0,
            Self::Channel1 => command::CHANNEL_1,
            Self::Channel2 => command::CHANNEL_2,
        }
    }

    pub const fn readback_bit(&self) -> u8 {
        match self {
            Self::Channel0 => command::READBACK_CH0,
            Self::Channel1 => command::READBACK_CH1,
            Self::Channel2 => command::READBACK_CH2,
        }
    }

    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::Channel0),
            1 => Some(Self::Channel1),
            2 => Some(Self::Channel2),
            _ => None,
        }
    }
}
