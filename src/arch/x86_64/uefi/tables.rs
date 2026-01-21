// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::RUNTIME_SERVICES_SIGNATURE;
use super::crc;
use super::error::UefiError;
use super::types::Guid;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

impl TableHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn verify_signature(&self, expected: u64) -> Result<(), UefiError> {
        if self.signature != expected {
            return Err(UefiError::InvalidSignature {
                expected,
                found: self.signature,
            });
        }
        Ok(())
    }

    // SAFETY: Caller must ensure the raw pointer points to valid memory of at least header_size bytes
    pub unsafe fn verify_crc(&self, base: *const u8) -> Result<(), UefiError> {
        if self.header_size < Self::SIZE as u32 {
            return Err(UefiError::InvalidParameter {
                param: "header_size",
            });
        }

        let header_bytes = core::slice::from_raw_parts(base, self.header_size as usize);
        let computed = crc::compute_table_crc(header_bytes, 16);

        if computed != self.crc32 {
            return Err(UefiError::CrcMismatch {
                expected: self.crc32,
                computed,
            });
        }
        Ok(())
    }

    pub fn major_version(&self) -> u16 {
        (self.revision >> 16) as u16
    }

    pub fn minor_version(&self) -> u16 {
        self.revision as u16
    }
}

#[repr(C)]
pub struct RuntimeServices {
    pub header: TableHeader,
    pub get_time: extern "efiapi" fn(*mut EfiTime, *mut EfiTimeCapabilities) -> u64,
    pub set_time: extern "efiapi" fn(*const EfiTime) -> u64,
    pub get_wakeup_time: extern "efiapi" fn(*mut u8, *mut u8, *mut EfiTime) -> u64,
    pub set_wakeup_time: extern "efiapi" fn(u8, *const EfiTime) -> u64,
    pub set_virtual_address_map: extern "efiapi" fn(u64, u64, u32, *const u8) -> u64,
    pub convert_pointer: extern "efiapi" fn(u64, *mut *const u8) -> u64,
    pub get_variable:
        extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut u64, *mut u8) -> u64,
    pub get_next_variable_name: extern "efiapi" fn(*mut u64, *mut u16, *mut Guid) -> u64,
    pub set_variable: extern "efiapi" fn(*const u16, *const Guid, u32, u64, *const u8) -> u64,
    pub get_next_high_mono_count: extern "efiapi" fn(*mut u32) -> u64,
    pub reset_system: extern "efiapi" fn(u32, u64, u64, *const u8) -> !,
    pub update_capsule: extern "efiapi" fn(*const *const u8, u64, u64) -> u64,
    pub query_capsule_capabilities:
        extern "efiapi" fn(*const *const u8, u64, *mut u64, *mut u32) -> u64,
    pub query_variable_info: extern "efiapi" fn(u32, *mut u64, *mut u64, *mut u64) -> u64,
}

impl RuntimeServices {
    // SAFETY: Caller must ensure ptr points to valid RuntimeServices table
    pub unsafe fn validate(ptr: *const Self) -> Result<(), UefiError> {
        if ptr.is_null() {
            return Err(UefiError::NullPointer {
                context: "runtime_services",
            });
        }

        let header = core::ptr::read_volatile(ptr as *const TableHeader);
        header.verify_signature(RUNTIME_SERVICES_SIGNATURE)?;
        header.verify_crc(ptr as *const u8)?;

        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

impl EfiTime {
    pub const TIMEZONE_UNSPECIFIED: i16 = 0x07FF;
    pub const DAYLIGHT_ADJUST: u8 = 0x01;
    pub const DAYLIGHT_IN_DAYLIGHT: u8 = 0x02;

    pub fn is_valid(&self) -> bool {
        self.year >= 1900
            && self.year <= 9999
            && self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= 31
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self.nanosecond <= 999_999_999
            && (self.timezone == Self::TIMEZONE_UNSPECIFIED
                || (self.timezone >= -1440 && self.timezone <= 1440))
    }

    pub fn to_unix_timestamp(&self) -> i64 {
        let days_per_month: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        let mut year = self.year as i64;
        let month = self.month as i64;
        let day = self.day as i64;

        let mut days: i64 = 0;

        for y in 1970..year {
            days += if Self::is_leap_year(y as u16) {
                366
            } else {
                365
            };
        }

        for m in 1..month {
            days += days_per_month[(m - 1) as usize];
            if m == 2 && Self::is_leap_year(year as u16) {
                days += 1;
            }
        }

        days += day - 1;

        let seconds = days * 86400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64;

        if self.timezone != Self::TIMEZONE_UNSPECIFIED {
            seconds - (self.timezone as i64 * 60)
        } else {
            seconds
        }
    }

    fn is_leap_year(year: u16) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTimeCapabilities {
    pub resolution: u32,
    pub accuracy: u32,
    pub sets_to_zero: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub const EFI_MEMORY_UC: u64 = 0x0000000000000001;
    pub const EFI_MEMORY_WC: u64 = 0x0000000000000002;
    pub const EFI_MEMORY_WT: u64 = 0x0000000000000004;
    pub const EFI_MEMORY_WB: u64 = 0x0000000000000008;
    pub const EFI_MEMORY_UCE: u64 = 0x0000000000000010;
    pub const EFI_MEMORY_WP: u64 = 0x0000000000001000;
    pub const EFI_MEMORY_RP: u64 = 0x0000000000002000;
    pub const EFI_MEMORY_XP: u64 = 0x0000000000004000;
    pub const EFI_MEMORY_NV: u64 = 0x0000000000008000;
    pub const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000000000010000;
    pub const EFI_MEMORY_RO: u64 = 0x0000000000020000;
    pub const EFI_MEMORY_SP: u64 = 0x0000000000040000;
    pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x0000000000080000;
    pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;

    pub fn size_bytes(&self) -> u64 {
        self.number_of_pages * 4096
    }

    pub fn end_address(&self) -> u64 {
        self.physical_start + self.size_bytes()
    }

    pub fn is_runtime(&self) -> bool {
        self.attribute & Self::EFI_MEMORY_RUNTIME != 0
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.memory_type, 7 | 1 | 2 | 3 | 4)
    }
}

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
        matches!(
            self,
            Self::ReservedMemoryType | Self::UnusableMemory | Self::MemoryMappedIO
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_header_version() {
        let header = TableHeader {
            signature: 0,
            revision: 0x00020008,
            header_size: 24,
            crc32: 0,
            reserved: 0,
        };
        assert_eq!(header.major_version(), 2);
        assert_eq!(header.minor_version(), 8);
    }

    #[test]
    fn test_efi_time_valid() {
        let time = EfiTime {
            year: 2026,
            month: 1,
            day: 21,
            hour: 12,
            minute: 30,
            second: 45,
            pad1: 0,
            nanosecond: 0,
            timezone: EfiTime::TIMEZONE_UNSPECIFIED,
            daylight: 0,
            pad2: 0,
        };
        assert!(time.is_valid());
    }

    #[test]
    fn test_efi_time_invalid() {
        let mut time = EfiTime::default();
        time.year = 2026;
        time.month = 13;
        assert!(!time.is_valid());
    }

    #[test]
    fn test_memory_type_usable() {
        assert!(MemoryType::ConventionalMemory.is_usable());
        assert!(MemoryType::LoaderCode.is_usable());
        assert!(!MemoryType::ReservedMemoryType.is_usable());
    }

    #[test]
    fn test_memory_descriptor_size() {
        let desc = MemoryDescriptor {
            memory_type: 7,
            physical_start: 0x1000,
            virtual_start: 0,
            number_of_pages: 10,
            attribute: 0,
        };
        assert_eq!(desc.size_bytes(), 40960);
        assert_eq!(desc.end_address(), 0x1000 + 40960);
    }
}
