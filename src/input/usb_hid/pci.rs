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

//! PCI bus scanning and xHCI controller detection

use crate::sys::io::{inl, outl};
use crate::sys::serial;

// PCI Constants
pub(crate) const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub(crate) const PCI_CONFIG_DATA: u16 = 0xCFC;

pub(crate) const XHCI_CLASS: u8 = 0x0C;
pub(crate) const XHCI_SUBCLASS: u8 = 0x03;
pub(crate) const XHCI_PROGIF: u8 = 0x30;

pub(crate) fn pci_addr(b: u8, d: u8, f: u8, o: u8) -> u32 {
    0x8000_0000 | ((b as u32)<<16) | ((d as u32)<<11) | ((f as u32)<<8) | ((o as u32)&0xFC)
}

pub(crate) fn pci_r32(b: u8, d: u8, f: u8, o: u8) -> u32 {
    unsafe { outl(PCI_CONFIG_ADDRESS, pci_addr(b,d,f,o)); inl(PCI_CONFIG_DATA) }
}

pub(crate) fn pci_w32(b: u8, d: u8, f: u8, o: u8, v: u32) {
    unsafe { outl(PCI_CONFIG_ADDRESS, pci_addr(b,d,f,o)); outl(PCI_CONFIG_DATA, v); }
}

/// Find xHCI controller on PCI bus
pub fn find_xhci() -> Option<(u8, u8, u8, u64)> {
    serial::println(b"[USB] Scanning PCI...");
    for b in 0u8..=255 {
        for d in 0u8..32 {
            let vid = pci_r32(b, d, 0, 0);
            if vid == 0xFFFFFFFF || vid == 0 { continue; }

            let cls = pci_r32(b, d, 0, 0x08);
            if ((cls >> 24) & 0xFF) as u8 == XHCI_CLASS
                && ((cls >> 16) & 0xFF) as u8 == XHCI_SUBCLASS
                && ((cls >> 8) & 0xFF) as u8 == XHCI_PROGIF {

                serial::print(b"[USB] xHCI at ");
                serial::print_hex(b as u64);
                serial::print(b":");
                serial::print_hex(d as u64);
                serial::println(b"");

                let bar0l = pci_r32(b, d, 0, 0x10);
                let bar0h = pci_r32(b, d, 0, 0x14);
                let bar = if (bar0l & 0x06) == 0x04 {
                    ((bar0h as u64) << 32) | ((bar0l & 0xFFFFFFF0) as u64)
                } else {
                    (bar0l & 0xFFFFFFF0) as u64
                };

                serial::print(b"[USB] BAR 0x");
                serial::print_hex(bar);
                serial::println(b"");

                let cmd = pci_r32(b, d, 0, 0x04);
                pci_w32(b, d, 0, 0x04, cmd | 0x06);

                return Some((b, d, 0, bar));
            }
        }
    }
    None
}
