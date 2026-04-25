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

use super::super::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionType {
    Code,
    Data,
    Stack,
    Heap,
    Device,
    Capsule,
}

impl RegionType {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Code => REGION_TYPE_CODE,
            Self::Data => REGION_TYPE_DATA,
            Self::Stack => REGION_TYPE_STACK,
            Self::Heap => REGION_TYPE_HEAP,
            Self::Device => REGION_TYPE_DEVICE,
            Self::Capsule => REGION_TYPE_CAPSULE,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Code => "Code",
            Self::Data => "Data",
            Self::Stack => "Stack",
            Self::Heap => "Heap",
            Self::Device => "Device",
            Self::Capsule => "Capsule",
        }
    }

    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Data | Self::Stack | Self::Heap | Self::Device)
    }

    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::Code)
    }
}
