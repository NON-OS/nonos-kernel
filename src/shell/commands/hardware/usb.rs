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
use crate::input::usb_hid;

pub fn cmd_lsusb() {
    print_line(b"USB Devices:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    if usb_hid::is_available() {
        print_line(b"Bus 001 Device 001: xHCI Host Controller", COLOR_TEXT);

        if usb_hid::keyboard_available() {
            print_line(b"Bus 001 Device 002: USB HID Keyboard", COLOR_GREEN);
        }

        if usb_hid::mouse_available() {
            print_line(b"Bus 001 Device 003: USB HID Mouse", COLOR_GREEN);
        }
    } else {
        print_line(b"(USB subsystem not available)", COLOR_TEXT_DIM);
        print_line(b"Using PS/2 fallback for input", COLOR_YELLOW);
    }

    let mut found_xhci = false;
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let vendor = pci::pci_read16(bus, device, 0, 0);
            if vendor == 0xFFFF {
                continue;
            }

            let class_code = pci::pci_read8(bus, device, 0, 11);
            let subclass = pci::pci_read8(bus, device, 0, 10);
            let progif = pci::pci_read8(bus, device, 0, 9);

            if class_code == 0x0C && subclass == 0x03 {
                if !found_xhci {
                    print_line(b"", COLOR_TEXT);
                    print_line(b"USB Controllers:", COLOR_TEXT_WHITE);
                    found_xhci = true;
                }

                let ctrl_type = match progif {
                    0x00 => b"  UHCI Controller (USB 1.x)     " as &[u8],
                    0x10 => b"  OHCI Controller (USB 1.x)     " as &[u8],
                    0x20 => b"  EHCI Controller (USB 2.0)     " as &[u8],
                    0x30 => b"  xHCI Controller (USB 3.x)     " as &[u8],
                    _ => b"  USB Controller                " as &[u8],
                };

                let color = if progif == 0x30 { COLOR_GREEN } else { COLOR_TEXT };
                print_line(ctrl_type, color);
            }
        }
    }
}
