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

#[cfg(test)]
mod tests {
    use super::super::header::TableHeader;
    use super::super::time::EfiTime;
    use super::super::memory::{MemoryDescriptor, MemoryType};

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
