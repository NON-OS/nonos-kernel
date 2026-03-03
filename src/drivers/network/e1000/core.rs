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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use super::constants::{REG_RAH0, REG_RAL0};
use super::global::find_e1000_device;
use crate::bus::pci::{enable_bus_master, enable_memory_space};
use crate::sys::serial;

pub struct E1000 {
    pub(super) mmio_base: u64,
    pub(super) mac: [u8; 6],
    pub(super) rx_cur: AtomicU32,
    pub(super) tx_cur: AtomicU32,
    pub(super) initialized: AtomicBool,
    pub(super) rx_queue: Mutex<Vec<Vec<u8>>>,
}

impl E1000 {
    pub fn new() -> Option<Self> {
        let dev = find_e1000_device()?;

        serial::print(b"[E1000] Found at ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::println(b"");

        enable_bus_master(dev.bus, dev.device, dev.function);
        enable_memory_space(dev.bus, dev.device, dev.function);

        let bar0 = dev.bar0 as u64;
        if bar0 == 0 {
            serial::println(b"[E1000] BAR0 is zero!");
            return None;
        }

        let mmio_base = bar0 & !0xF;
        serial::print(b"[E1000] MMIO base: 0x");
        serial::print_hex(mmio_base);
        serial::println(b"");

        serial::println(b"[E1000] Using static buffers...");

        Some(Self {
            mmio_base,
            mac: [0; 6],
            rx_cur: AtomicU32::new(0),
            tx_cur: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
            rx_queue: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn read_reg(&self, reg: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u32) }
    }

    pub(super) fn write_reg(&self, reg: u32, val: u32) {
        unsafe {
            core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u32, val);
        }
    }

    pub(super) fn read_mac(&mut self) {
        let ral = self.read_reg(REG_RAL0);
        let rah = self.read_reg(REG_RAH0);

        if ral != 0 || (rah & 0xFFFF) != 0 {
            self.mac[0] = (ral >> 0) as u8;
            self.mac[1] = (ral >> 8) as u8;
            self.mac[2] = (ral >> 16) as u8;
            self.mac[3] = (ral >> 24) as u8;
            self.mac[4] = (rah >> 0) as u8;
            self.mac[5] = (rah >> 8) as u8;
        } else {
            self.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        }

        serial::print(b"[E1000] MAC: ");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 {
                serial::print(b":");
            }
            serial::print_hex(b as u64);
        }
        serial::println(b"");
    }
}
