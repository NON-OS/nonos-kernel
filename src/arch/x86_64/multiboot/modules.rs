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
use x86_64::PhysAddr;

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub cmdline: Option<String>,
}

impl ModuleInfo {
    pub fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BasicMemInfo {
    pub mem_lower: u32,
    pub mem_upper: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct BiosBootDevice {
    pub bios_dev: u32,
    pub partition: u32,
    pub sub_partition: u32,
}

#[derive(Debug, Clone)]
pub struct VbeInfo {
    pub mode: u16,
    pub interface_seg: u16,
    pub interface_off: u16,
    pub interface_len: u16,
    pub control_info: [u8; 512],
    pub mode_info: [u8; 256],
}

#[derive(Debug, Clone)]
pub struct ElfSections {
    pub num: u32,
    pub entsize: u32,
    pub shndx: u32,
    pub sections: Vec<ElfSection>,
}

#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name_index: u32,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ApmTable {
    pub version: u16,
    pub cseg: u16,
    pub offset: u32,
    pub cseg_16: u16,
    pub dseg: u16,
    pub flags: u16,
    pub cseg_len: u16,
    pub cseg_16_len: u16,
    pub dseg_len: u16,
}

#[derive(Debug, Clone)]
pub struct AcpiRsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
    pub length: Option<u32>,
    pub xsdt_address: Option<u64>,
    pub extended_checksum: Option<u8>,
}

impl AcpiRsdp {
    pub fn is_acpi2(&self) -> bool {
        self.revision >= 2
    }

    pub fn table_address(&self) -> u64 {
        if let Some(xsdt) = self.xsdt_address {
            if xsdt != 0 {
                return xsdt;
            }
        }
        self.rsdt_address as u64
    }

    pub fn verify_checksum(&self) -> bool {
        let mut sum: u8 = 0;

        for &b in &self.signature {
            sum = sum.wrapping_add(b);
        }

        sum = sum.wrapping_add(self.checksum);

        for &b in &self.oem_id {
            sum = sum.wrapping_add(b);
        }

        sum = sum.wrapping_add(self.revision);

        let rsdt_bytes = self.rsdt_address.to_le_bytes();
        for &b in &rsdt_bytes {
            sum = sum.wrapping_add(b);
        }

        sum == 0
    }

    pub fn verify_extended_checksum(&self) -> bool {
        if !self.is_acpi2() {
            return true;
        }

        let mut sum: u8 = 0;

        for &b in &self.signature {
            sum = sum.wrapping_add(b);
        }
        sum = sum.wrapping_add(self.checksum);
        for &b in &self.oem_id {
            sum = sum.wrapping_add(b);
        }
        sum = sum.wrapping_add(self.revision);
        for &b in &self.rsdt_address.to_le_bytes() {
            sum = sum.wrapping_add(b);
        }

        if let Some(length) = self.length {
            for &b in &length.to_le_bytes() {
                sum = sum.wrapping_add(b);
            }
        }

        if let Some(xsdt) = self.xsdt_address {
            for &b in &xsdt.to_le_bytes() {
                sum = sum.wrapping_add(b);
            }
        }

        if let Some(ext_checksum) = self.extended_checksum {
            sum = sum.wrapping_add(ext_checksum);
        }

        sum == 0
    }
}

#[derive(Debug, Clone)]
pub struct SmbiosInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub table_address: PhysAddr,
    pub table_length: u32,
}
