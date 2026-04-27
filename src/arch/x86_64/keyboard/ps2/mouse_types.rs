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

use super::super::types::MouseButtons;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseType {
    Standard,
    Wheel,
    FiveButton,
}

impl MouseType {
    pub const fn packet_size(self) -> usize {
        match self {
            Self::Standard => 3,
            Self::Wheel | Self::FiveButton => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Count1PerMm = 0,
    Count2PerMm = 1,
    Count4PerMm = 2,
    Count8PerMm = 3,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MousePacket {
    pub buttons: MouseButtons,
    pub dx: i16,
    pub dy: i16,
    pub dz: i8,
}
