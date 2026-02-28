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
    use alloc::string::String;
    use alloc::vec;

    use crate::arch::x86_64::uefi::types::{Guid, VariableAttributes};
    use super::super::variable::UefiVariable;
    use super::super::utils::{name_to_ucs2, ucs2_to_string};
    use super::super::firmware::FirmwareInfo;
    use super::super::iterator::VariableIterator;

    #[test]
    fn test_variable_creation() {
        let var = UefiVariable::new(
            String::from("TestVar"),
            Guid::GLOBAL_VARIABLE,
            VariableAttributes::DEFAULT_NV_BS_RT,
            vec![1, 2, 3, 4],
        );

        assert_eq!(var.name, "TestVar");
        assert_eq!(var.guid, Guid::GLOBAL_VARIABLE);
        assert_eq!(var.data_len(), 4);
        assert!(!var.is_empty());
    }

    #[test]
    fn test_variable_as_u8() {
        let var = UefiVariable::new(
            String::from("Test"),
            Guid::GLOBAL_VARIABLE,
            VariableAttributes::NONE,
            vec![0x42],
        );
        assert_eq!(var.as_u8(), Some(0x42));
    }

    #[test]
    fn test_variable_as_u32() {
        let var = UefiVariable::new(
            String::from("Test"),
            Guid::GLOBAL_VARIABLE,
            VariableAttributes::NONE,
            vec![0x78, 0x56, 0x34, 0x12],
        );
        assert_eq!(var.as_u32(), Some(0x12345678));
    }

    #[test]
    fn test_variable_as_bool() {
        let var_true = UefiVariable::new(
            String::from("Test"),
            Guid::GLOBAL_VARIABLE,
            VariableAttributes::NONE,
            vec![1],
        );
        assert!(var_true.as_bool());

        let var_false = UefiVariable::new(
            String::from("Test"),
            Guid::GLOBAL_VARIABLE,
            VariableAttributes::NONE,
            vec![0],
        );
        assert!(!var_false.as_bool());
    }

    #[test]
    fn test_name_to_ucs2() {
        let result = name_to_ucs2("Test").unwrap();
        assert_eq!(result[0], 'T' as u16);
        assert_eq!(result[1], 'e' as u16);
        assert_eq!(result[2], 's' as u16);
        assert_eq!(result[3], 't' as u16);
        assert_eq!(result[4], 0);
    }

    #[test]
    fn test_ucs2_to_string() {
        let ucs2 = ['H' as u16, 'i' as u16, 0, 0, 0];
        let s = ucs2_to_string(&ucs2);
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_firmware_info_default() {
        let info = FirmwareInfo::default();
        assert_eq!(info.vendor, "Unknown");
        assert!(!info.secure_boot_enabled);
        assert!(info.setup_mode);
    }

    #[test]
    fn test_firmware_info_version() {
        let info = FirmwareInfo {
            revision: 0x00020008,
            ..Default::default()
        };
        assert_eq!(info.uefi_major_version(), 2);
        assert_eq!(info.uefi_minor_version(), 8);
    }

    #[test]
    fn test_variable_iterator() {
        let iter = VariableIterator::new();
        assert!(!iter.is_finished());
        assert!(iter.current_guid().is_null());
    }
}
