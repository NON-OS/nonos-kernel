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
    Available,
    Reserved,
    Kernel,
    Capsule,
    Hardware,
    Defective,
}

impl RegionType {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Available => REGION_TYPE_AVAILABLE,
            Self::Reserved => REGION_TYPE_RESERVED,
            Self::Kernel => REGION_TYPE_KERNEL,
            Self::Capsule => REGION_TYPE_CAPSULE,
            Self::Hardware => REGION_TYPE_HARDWARE,
            Self::Defective => REGION_TYPE_DEFECTIVE,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Reserved => "Reserved",
            Self::Kernel => "Kernel",
            Self::Capsule => "Capsule",
            Self::Hardware => "Hardware",
            Self::Defective => "Defective",
        }
    }

    pub const fn is_allocatable(&self) -> bool {
        matches!(self, Self::Available)
    }
}
