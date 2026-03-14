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

use core::convert::TryFrom;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Reserved = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    Conventional = 7,
    Unusable = 8,
    ACPIReclaim = 9,
    ACPINvs = 10,
    MemoryMappedIO = 11,
    MemoryMappedIOPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMemoryType(pub u32);

impl TryFrom<u32> for MemoryType {
    type Error = InvalidMemoryType;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::LoaderCode),
            2 => Ok(Self::LoaderData),
            3 => Ok(Self::BootServicesCode),
            4 => Ok(Self::BootServicesData),
            5 => Ok(Self::RuntimeServicesCode),
            6 => Ok(Self::RuntimeServicesData),
            7 => Ok(Self::Conventional),
            8 => Ok(Self::Unusable),
            9 => Ok(Self::ACPIReclaim),
            10 => Ok(Self::ACPINvs),
            11 => Ok(Self::MemoryMappedIO),
            12 => Ok(Self::MemoryMappedIOPortSpace),
            13 => Ok(Self::PalCode),
            14 => Ok(Self::PersistentMemory),
            _ => Err(InvalidMemoryType(value)),
        }
    }
}

impl MemoryType {
    pub fn is_usable(&self) -> bool {
        matches!(
            self,
            MemoryType::Conventional
                | MemoryType::BootServicesCode
                | MemoryType::BootServicesData
                | MemoryType::LoaderCode
                | MemoryType::LoaderData
        )
    }

    pub fn from_u32_or_reserved(value: u32) -> Self {
        Self::try_from(value).unwrap_or(Self::Reserved)
    }
}
