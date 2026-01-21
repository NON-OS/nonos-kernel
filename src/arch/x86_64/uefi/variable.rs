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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::constants::MAX_VARIABLE_NAME_LENGTH;
use super::error::UefiError;
use super::types::{Guid, VariableAttributes};

#[derive(Debug, Clone)]
pub struct UefiVariable {
    pub name: String,
    pub guid: Guid,
    pub attributes: VariableAttributes,
    pub data: Vec<u8>,
}

impl UefiVariable {
    pub fn new(name: String, guid: Guid, attributes: VariableAttributes, data: Vec<u8>) -> Self {
        Self {
            name,
            guid,
            attributes,
            data,
        }
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_non_volatile(&self) -> bool {
        self.attributes.is_non_volatile()
    }

    pub fn is_runtime_accessible(&self) -> bool {
        self.attributes.is_runtime_access()
    }

    pub fn as_u8(&self) -> Option<u8> {
        if self.data.len() == 1 {
            Some(self.data[0])
        } else {
            None
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        if self.data.len() >= 2 {
            Some(u16::from_le_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
                self.data[7],
            ]))
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> bool {
        !self.data.is_empty() && self.data[0] != 0
    }

    pub fn as_string(&self) -> Option<String> {
        if self.data.is_empty() {
            return Some(String::new());
        }

        if self.data.len() % 2 == 0 {
            let chars: Vec<u16> = self
                .data
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();

            String::from_utf16(&chars).ok()
        } else {
            let end = self.data.iter().position(|&b| b == 0).unwrap_or(self.data.len());
            String::from_utf8(self.data[..end].to_vec()).ok()
        }
    }
}

pub fn name_to_ucs2(name: &str) -> Result<[u16; MAX_VARIABLE_NAME_LENGTH], UefiError> {
    if name.len() >= MAX_VARIABLE_NAME_LENGTH {
        return Err(UefiError::VariableNameTooLong {
            length: name.len(),
            max_length: MAX_VARIABLE_NAME_LENGTH - 1,
        });
    }

    let mut buf = [0u16; MAX_VARIABLE_NAME_LENGTH];
    for (i, ch) in name.chars().enumerate() {
        if i >= MAX_VARIABLE_NAME_LENGTH - 1 {
            break;
        }
        buf[i] = ch as u16;
    }
    Ok(buf)
}

pub fn ucs2_to_string(ucs2: &[u16]) -> String {
    let end = ucs2.iter().position(|&c| c == 0).unwrap_or(ucs2.len());
    String::from_utf16_lossy(&ucs2[..end])
}

#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub version: String,
    pub revision: u32,
    pub firmware_revision: u32,
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub variable_support: bool,
    pub runtime_services_supported: bool,
}

impl FirmwareInfo {
    pub fn uefi_major_version(&self) -> u16 {
        (self.revision >> 16) as u16
    }

    pub fn uefi_minor_version(&self) -> u16 {
        self.revision as u16
    }
}

impl Default for FirmwareInfo {
    fn default() -> Self {
        Self {
            vendor: String::from("Unknown"),
            version: String::from("0.0"),
            revision: 0,
            firmware_revision: 0,
            secure_boot_enabled: false,
            setup_mode: true,
            variable_support: false,
            runtime_services_supported: false,
        }
    }
}

pub struct VariableIterator {
    current_name: [u16; MAX_VARIABLE_NAME_LENGTH],
    current_guid: Guid,
    finished: bool,
}

impl VariableIterator {
    pub fn new() -> Self {
        Self {
            current_name: [0u16; MAX_VARIABLE_NAME_LENGTH],
            current_guid: Guid::null(),
            finished: false,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn current_name_ucs2(&self) -> &[u16; MAX_VARIABLE_NAME_LENGTH] {
        &self.current_name
    }

    pub fn current_name_ucs2_mut(&mut self) -> &mut [u16; MAX_VARIABLE_NAME_LENGTH] {
        &mut self.current_name
    }

    pub fn current_guid(&self) -> &Guid {
        &self.current_guid
    }

    pub fn current_guid_mut(&mut self) -> &mut Guid {
        &mut self.current_guid
    }

    pub fn set_finished(&mut self) {
        self.finished = true;
    }

    pub fn current_name_string(&self) -> String {
        ucs2_to_string(&self.current_name)
    }
}

impl Default for VariableIterator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
