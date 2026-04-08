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
    pub fn is_acpi2(&self) -> bool { self.revision >= 2 }

    pub fn table_address(&self) -> u64 {
        if let Some(xsdt) = self.xsdt_address { if xsdt != 0 { return xsdt; } }
        self.rsdt_address as u64
    }

    pub fn verify_checksum(&self) -> bool {
        let mut sum: u8 = 0;
        for &b in &self.signature { sum = sum.wrapping_add(b); }
        sum = sum.wrapping_add(self.checksum);
        for &b in &self.oem_id { sum = sum.wrapping_add(b); }
        sum = sum.wrapping_add(self.revision);
        for &b in &self.rsdt_address.to_le_bytes() { sum = sum.wrapping_add(b); }
        sum == 0
    }

    pub fn verify_extended_checksum(&self) -> bool {
        if !self.is_acpi2() { return true; }
        let mut sum: u8 = 0;
        for &b in &self.signature { sum = sum.wrapping_add(b); }
        sum = sum.wrapping_add(self.checksum);
        for &b in &self.oem_id { sum = sum.wrapping_add(b); }
        sum = sum.wrapping_add(self.revision);
        for &b in &self.rsdt_address.to_le_bytes() { sum = sum.wrapping_add(b); }
        if let Some(len) = self.length { for &b in &len.to_le_bytes() { sum = sum.wrapping_add(b); } }
        if let Some(xsdt) = self.xsdt_address { for &b in &xsdt.to_le_bytes() { sum = sum.wrapping_add(b); } }
        if let Some(ext) = self.extended_checksum { sum = sum.wrapping_add(ext); }
        sum == 0
    }
}
