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

pub fn init() {
    serial::println(b"[USB] USB HID init...");
    if let Some((_, _, _, bar)) = find_xhci() {
        if bar != 0 && bar < 0xFFFF_FFFF_0000 {
            if init_xhci(bar) {
                serial::println(b"[USB] USB HID ready");
            }
        }
    } else {
        serial::println(b"[USB] No xHCI");
    }
}
