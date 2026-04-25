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

use alloc::vec::Vec;
use core::ptr;

use crate::arch::x86_64::acpi::parser;

pub fn enumerate_pci_raw() -> Vec<(u16, u8, u8, u8)> {
    let mut devices = Vec::new();
    for seg in parser::pcie_segments() {
        for bus in seg.start_bus..=seg.end_bus {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    if let Some(config_addr) = seg.config_address(bus, device, function, 0) {
                        unsafe {
                            let vendor_id = ptr::read_volatile(config_addr as *const u16);
                            if vendor_id != 0xFFFF {
                                devices.push((seg.segment, bus, device, function));
                                if function == 0 {
                                    let header_type =
                                        ptr::read_volatile((config_addr + 0x0E) as *const u8);
                                    if header_type & 0x80 == 0 {
                                        break;
                                    }
                                }
                            } else if function == 0 {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    devices
}
