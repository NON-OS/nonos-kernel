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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::bus::pci;
use crate::mem::pmm;
use crate::shell::commands::utils::format_size;

pub fn cmd_lsblk() {
    print_line(b"Block Devices:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"NAME        TYPE      SIZE    STATUS", COLOR_TEXT_DIM);

    print_line(b"ramfs       ram       -       mounted /", COLOR_GREEN);

    if pmm::is_init() {
        let (total, _used, _free) = pmm::memory_stats();
        let mut line = [0u8; 64];
        line[..12].copy_from_slice(b"pmm         ");
        line[12..22].copy_from_slice(b"memory    ");
        let len = format_size(&mut line[22..], total);
        line[22+len..22+len+8].copy_from_slice(b"  active");
        print_line(&line[..22+len+8], COLOR_GREEN);
    }

    let mut found_storage = false;
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let vendor = pci::pci_read16(bus, device, 0, 0);
            if vendor == 0xFFFF {
                continue;
            }

            let class_code = pci::pci_read8(bus, device, 0, 11);
            let subclass = pci::pci_read8(bus, device, 0, 10);

            if class_code == 0x01 {
                found_storage = true;
                let mut line = [0u8; 64];

                let (name, type_str) = match subclass {
                    0x06 => (b"sata0       " as &[u8], b"disk      " as &[u8]),
                    0x08 => (b"nvme0       " as &[u8], b"nvme      " as &[u8]),
                    0x01 => (b"ide0        " as &[u8], b"ide       " as &[u8]),
                    _ => (b"blk0        " as &[u8], b"block     " as &[u8]),
                };

                line[..12].copy_from_slice(name);
                line[12..22].copy_from_slice(type_str);
                line[22..30].copy_from_slice(b"?       ");
                line[30..44].copy_from_slice(b"detected    ");
                print_line(&line[..44], COLOR_YELLOW);
            }
        }
    }

    if !found_storage {
        print_line(b"(no physical storage detected)", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Note: N\xd8NOS runs in ZeroState (RAM-only)", COLOR_YELLOW);
}
