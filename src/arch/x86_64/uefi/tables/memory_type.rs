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

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    ACPIReclaimMemory = 9,
    ACPIMemoryNVS = 10,
    MemoryMappedIO = 11,
    MemoryMappedIOPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    UnacceptedMemoryType = 15,
    MaxMemoryType = 16,
}

impl MemoryType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::ReservedMemoryType),
            1 => Some(Self::LoaderCode),
            2 => Some(Self::LoaderData),
            3 => Some(Self::BootServicesCode),
            4 => Some(Self::BootServicesData),
            5 => Some(Self::RuntimeServicesCode),
            6 => Some(Self::RuntimeServicesData),
            7 => Some(Self::ConventionalMemory),
            8 => Some(Self::UnusableMemory),
            9 => Some(Self::ACPIReclaimMemory),
            10 => Some(Self::ACPIMemoryNVS),
            11 => Some(Self::MemoryMappedIO),
            12 => Some(Self::MemoryMappedIOPortSpace),
            13 => Some(Self::PalCode),
            14 => Some(Self::PersistentMemory),
            15 => Some(Self::UnacceptedMemoryType),
            _ => None,
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(
            self,
            Self::LoaderCode
                | Self::LoaderData
                | Self::BootServicesCode
                | Self::BootServicesData
                | Self::ConventionalMemory
        )
    }

    pub fn is_reserved(self) -> bool {
        matches!(self, Self::ReservedMemoryType | Self::UnusableMemory | Self::MemoryMappedIO)
    }
}
