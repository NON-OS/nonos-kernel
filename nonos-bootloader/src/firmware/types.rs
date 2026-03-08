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

/*
Firmware handoff types for bootloader -> kernel transfer.
Supports Intel and Realtek WiFi chipsets with specific firmware
variants for each chip family.
*/

pub const MAX_FIRMWARE_ENTRIES: usize = 16;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareType {
    Unknown = 0,
    IntelAx200 = 1,
    IntelAx210 = 2,
    Intel8265 = 3,
    Intel9260 = 4,
    Intel7265 = 5,
    Rtl8821c = 10,
    Rtl8822b = 11,
    Rtl8822c = 12,
    Rtl8723d = 13,
    Rtl8851b = 14,
    Rtl8852a = 15,
    Rtl8852b = 16,
    Rtl8852c = 17,
}

impl Default for FirmwareType {
    fn default() -> Self {
        FirmwareType::Unknown
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FirmwareEntry {
    pub fw_type: FirmwareType,
    pub ptr: u64,
    pub size: u32,
    pub reserved: u32,
}

impl FirmwareEntry {
    pub const fn empty() -> Self {
        Self {
            fw_type: FirmwareType::Unknown,
            ptr: 0,
            size: 0,
            reserved: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.ptr != 0 && self.size > 0 && self.fw_type != FirmwareType::Unknown
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FirmwareHandoff {
    pub count: usize,
    pub entries: [FirmwareEntry; MAX_FIRMWARE_ENTRIES],
}

impl Default for FirmwareHandoff {
    fn default() -> Self {
        Self {
            count: 0,
            entries: [FirmwareEntry::empty(); MAX_FIRMWARE_ENTRIES],
        }
    }
}

impl FirmwareHandoff {
    pub fn get(&self, fw_type: FirmwareType) -> Option<&FirmwareEntry> {
        for i in 0..self.count {
            if self.entries[i].fw_type == fw_type {
                return Some(&self.entries[i]);
            }
        }
        None
    }

    pub fn has_firmware(&self, fw_type: FirmwareType) -> bool {
        self.get(fw_type).is_some()
    }
}
