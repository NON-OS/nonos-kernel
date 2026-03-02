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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};
use crate::bus::pci;
use crate::shell::commands::utils::{format_hex_byte, format_num_simple};

pub fn cmd_lspci() {
    print_line(b"PCI Devices:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"BUS:DEV.FN  CLASS    VENDOR:DEVICE  NAME", COLOR_TEXT_DIM);

    let mut count = 0u32;

    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for func in 0..8u8 {
                let vendor = pci::pci_read16(bus, device, func, 0);
                if vendor == 0xFFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }

                let device_id = pci::pci_read16(bus, device, func, 2);
                let class_code = pci::pci_read8(bus, device, func, 11);
                let subclass = pci::pci_read8(bus, device, func, 10);

                let mut line = [0u8; 80];
                let mut pos = 0;

                format_hex_byte(&mut line[pos..pos+2], bus);
                pos += 2;
                line[pos] = b':';
                pos += 1;
                format_hex_byte(&mut line[pos..pos+2], device);
                pos += 2;
                line[pos] = b'.';
                pos += 1;
                line[pos] = b'0' + func;
                pos += 1;

                while pos < 12 {
                    line[pos] = b' ';
                    pos += 1;
                }

                let class_name = pci_class_name(class_code, subclass);
                let class_len = class_name.len().min(8);
                line[pos..pos+class_len].copy_from_slice(&class_name[..class_len]);
                pos += class_len;
                while pos < 21 {
                    line[pos] = b' ';
                    pos += 1;
                }

                format_hex_byte(&mut line[pos..pos+2], (vendor >> 8) as u8);
                pos += 2;
                format_hex_byte(&mut line[pos..pos+2], vendor as u8);
                pos += 2;
                line[pos] = b':';
                pos += 1;
                format_hex_byte(&mut line[pos..pos+2], (device_id >> 8) as u8);
                pos += 2;
                format_hex_byte(&mut line[pos..pos+2], device_id as u8);
                pos += 2;

                while pos < 36 {
                    line[pos] = b' ';
                    pos += 1;
                }

                let dev_name = pci_device_name(vendor, device_id, class_code);
                let name_len = dev_name.len().min(40);
                line[pos..pos+name_len].copy_from_slice(&dev_name[..name_len]);
                pos += name_len;

                let color = match class_code {
                    0x01 => COLOR_YELLOW,
                    0x02 => COLOR_GREEN,
                    0x03 => COLOR_ACCENT,
                    0x06 => COLOR_TEXT_DIM,
                    0x0C => COLOR_GREEN,
                    _ => COLOR_TEXT,
                };

                print_line(&line[..pos], color);
                count += 1;

                if func == 0 {
                    let header_type = pci::pci_read8(bus, device, func, 14);
                    if header_type & 0x80 == 0 {
                        break;
                    }
                }
            }
        }
    }

    print_line(b"", COLOR_TEXT);
    let mut total_line = [0u8; 32];
    total_line[..7].copy_from_slice(b"Total: ");
    let len = format_num_simple(&mut total_line[7..], count as usize);
    total_line[7+len..7+len+8].copy_from_slice(b" devices");
    print_line(&total_line[..7+len+8], COLOR_TEXT_DIM);
}

fn pci_class_name(class: u8, subclass: u8) -> &'static [u8] {
    match class {
        0x00 => b"Unclass ",
        0x01 => match subclass {
            0x01 => b"IDE     ",
            0x06 => b"SATA    ",
            0x08 => b"NVMe    ",
            _ => b"Storage ",
        },
        0x02 => match subclass {
            0x00 => b"Ethernet",
            0x80 => b"WiFi    ",
            _ => b"Network ",
        },
        0x03 => b"Display ",
        0x04 => b"Media   ",
        0x05 => b"Memory  ",
        0x06 => match subclass {
            0x00 => b"HostBr  ",
            0x01 => b"ISABr   ",
            0x04 => b"PCIBr   ",
            _ => b"Bridge  ",
        },
        0x07 => b"Comm    ",
        0x08 => b"System  ",
        0x09 => b"Input   ",
        0x0C => match subclass {
            0x03 => b"USB     ",
            0x05 => b"SMBus   ",
            _ => b"Serial  ",
        },
        0x0D => b"Wireless",
        0x12 => b"Encrypt ",
        _ => b"Other   ",
    }
}

fn pci_device_name(vendor: u16, device_id: u16, class: u8) -> &'static [u8] {
    match vendor {
        0x8086 => match device_id {
            0x100E => b"Intel E1000 GbE",
            0x10D3 => b"Intel 82574L GbE",
            0x2922 => b"Intel ICH9 AHCI",
            0x2723 => b"Intel AX200 WiFi",
            0x2725 => b"Intel AX210 WiFi",
            0x9A03 => b"Intel TGL Graphics",
            0xA0C8 => b"Intel USB xHCI",
            _ => match class {
                0x02 => b"Intel Network",
                0x03 => b"Intel Graphics",
                0x0C => b"Intel USB",
                _ => b"Intel Device",
            },
        },
        0x1B36 => match device_id {
            0x000D => b"QEMU XHCI USB",
            _ => b"QEMU Device",
        },
        0x1234 => b"QEMU VGA",
        0x10EC => b"Realtek NIC",
        0x14E4 => b"Broadcom Device",
        0x10DE => b"NVIDIA GPU",
        0x1002 => b"AMD/ATI GPU",
        0x1022 => b"AMD Chipset",
        _ => b"Unknown Device",
    }
}
