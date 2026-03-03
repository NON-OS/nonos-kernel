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
    use crate::drivers::nvme::{constants, types};

    #[test]
    fn test_controller_capabilities() {
        let cap: u64 = 0x00FF_0000_0020_00FF;
        let caps = types::ControllerCapabilities::from_register(cap);

        assert_eq!(caps.max_queue_entries, 256);
        assert!(caps.timeout_500ms_units > 0);
    }

    #[test]
    fn test_controller_version() {
        let vs: u32 = 0x0001_0400;
        let version = types::ControllerVersion::from_register(vs);

        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 4);
        assert_eq!(version.tertiary, 0);
        assert!(version.is_at_least(1, 3));
        assert!(version.is_at_least(1, 4));
        assert!(!version.is_at_least(1, 5));
    }

    #[test]
    fn test_lba_format() {
        let dword: u32 = 0x0000_0900;
        let format = types::LbaFormat::from_dword(dword);

        assert_eq!(format.lba_data_size_shift, 9);
        assert_eq!(format.lba_size(), 512);
        assert_eq!(format.metadata_size, 0);
    }

    #[test]
    fn test_lba_format_4k() {
        let dword: u32 = 0x0000_0C00;
        let format = types::LbaFormat::from_dword(dword);

        assert_eq!(format.lba_data_size_shift, 12);
        assert_eq!(format.lba_size(), 4096);
    }

    #[test]
    fn test_dsm_range() {
        let range = types::DsmRange::new(0x1000, 8, constants::DSM_ATTR_DEALLOCATE);

        assert_eq!(range.starting_lba, 0x1000);
        assert_eq!(range.lba_count, 8);
        assert_eq!(range.context_attributes, constants::DSM_ATTR_DEALLOCATE);
    }
}
