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

use core::sync::atomic::{AtomicBool, AtomicU32};

pub(super) const PCI_CONFIG_ADDRESS: u16 = 0x0CF8;
pub(super) const PCI_CONFIG_DATA: u16 = 0x0CFC;
pub(super) const MAX_DEVICES: usize = 64;

pub(super) static PCI_INIT: AtomicBool = AtomicBool::new(false);
pub(super) static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);
pub(super) static mut DEVICES: [PciDevice; MAX_DEVICES] = [PciDevice::empty(); MAX_DEVICES];

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub bar0: u32,
    pub bar1: u32,
    pub bar2: u32,
    pub bar3: u32,
    pub bar4: u32,
    pub bar5: u32,
    pub irq_line: u8,
    pub irq_pin: u8,
}

impl PciDevice {
    pub const fn empty() -> Self {
        Self {
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0xFFFF,
            device_id: 0xFFFF,
            class: 0,
            subclass: 0,
            prog_if: 0,
            header_type: 0,
            bar0: 0,
            bar1: 0,
            bar2: 0,
            bar3: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 0,
            irq_pin: 0,
        }
    }
    pub fn is_valid(&self) -> bool {
        self.vendor_id != 0xFFFF
    }
}
