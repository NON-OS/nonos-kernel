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

use uefi::prelude::*;

use crate::log::logger::log_debug;

use super::types::RsdpDescriptor;

pub fn discover_acpi_rsdp(system_table: &mut SystemTable<Boot>) -> Option<u64> {
    for entry in system_table.config_table() {
        if entry.guid == uefi::table::cfg::ACPI2_GUID || entry.guid == uefi::table::cfg::ACPI_GUID {
            let rsdp_ptr = entry.address as u64;
            if validate_rsdp(rsdp_ptr) {
                return Some(rsdp_ptr);
            }
        }
    }
    None
}

fn validate_rsdp(rsdp_address: u64) -> bool {
    unsafe {
        let rsdp = &*(rsdp_address as *const RsdpDescriptor);
        if &rsdp.signature != RsdpDescriptor::SIGNATURE {
            return false;
        }

        let bytes = core::slice::from_raw_parts(rsdp_address as *const u8, 20);
        let sum: u8 = bytes.iter().fold(0, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

pub fn get_cpu_count_from_acpi(_rsdp_address: u64) -> usize {
    log_debug(
        "acpi",
        "MADT parsing for CPU count not implemented; defaulting to 1",
    );
    1
}
