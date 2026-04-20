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

use crate::sys::serial;
use super::pci::find_xhci;
use super::xhci::init_xhci;

/// The kernel inherits UEFI page tables which identity-map all PCI BARs.
/// The framebuffer already works this way (raw physical address used as VA).
/// We use the same approach for the xHCI BAR — no page table walking needed.

pub fn init() {
    serial::println(b"[USB] USB HID init...");
    if let Some((_, _, _, bar)) = find_xhci() {
        if bar == 0 {
            serial::println(b"[USB] BAR is zero");
            return;
        }
        serial::print(b"[USB] BAR=0x");
        serial::print_hex(bar);
        serial::println(b"");

        // Use BAR physical address directly as VA — UEFI identity-maps PCI BARs
        // (same approach as the framebuffer which works via handoff.fb.ptr)
        serial::println(b"[USB] Testing UEFI identity-mapped access...");
        let test_val = unsafe { core::ptr::read_volatile(bar as *const u32) };
        serial::print(b"[USB] CAPLENGTH reg=0x");
        serial::print_hex(test_val as u64);
        serial::println(b"");

        // CAPLENGTH is in bits [7:0], should be small (typically 0x20)
        // HCIVERSION is in bits [31:16], should be 0x0100 or 0x0110
        let caplen = test_val & 0xFF;
        let hciver = (test_val >> 16) & 0xFFFF;
        if caplen == 0 || caplen > 0x80 || hciver == 0 || hciver == 0xFFFF {
            serial::println(b"[USB] BAR read looks wrong, not identity-mapped?");
            return;
        }

        serial::print(b"[USB] xHCI caplen=");
        serial::print_dec(caplen as u64);
        serial::print(b" ver=0x");
        serial::print_hex(hciver as u64);
        serial::println(b"");

        if init_xhci(bar) {
            serial::println(b"[USB] USB HID ready");
        }
    } else {
        serial::println(b"[USB] No xHCI");
    }
}
