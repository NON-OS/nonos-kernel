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
use core::sync::atomic::{AtomicBool, AtomicU32};
use spin::Mutex;

use super::global::find_rtl8169_device;
use crate::bus::pci::{enable_bus_master, enable_memory_space};
use crate::sys::serial;

pub struct Rtl8169 {
    pub(super) mmio_base: u64,
    pub(super) mac: [u8; 6],
    pub(super) initialized: AtomicBool,
    pub(super) rx_cur: AtomicU32,
    pub(super) tx_cur: AtomicU32,
    pub(super) rx_queue: Mutex<Vec<Vec<u8>>>,
}

impl Rtl8169 {
    pub fn new() -> Option<Self> {
        let dev = find_rtl8169_device()?;

        serial::print(b"[RTL8169] Found at ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::println(b"");

        enable_bus_master(dev.bus, dev.device, dev.function);
        enable_memory_space(dev.bus, dev.device, dev.function);

        let mmio_base = (dev.bar1 & !0xF) as u64;
        if mmio_base == 0 {
            let io_bar = (dev.bar0 & !0x3) as u64;
            if io_bar == 0 {
                serial::println(b"[RTL8169] No valid BAR!");
                return None;
            }
        }

        serial::print(b"[RTL8169] MMIO base: 0x");
        serial::print_hex(mmio_base);
        serial::println(b"");

        Some(Self {
            mmio_base,
            mac: [0; 6],
            initialized: AtomicBool::new(false),
            rx_cur: AtomicU32::new(0),
            tx_cur: AtomicU32::new(0),
            rx_queue: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn read8(&self, reg: u32) -> u8 {
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u8) }
    }

    pub(super) fn write8(&self, reg: u32, val: u8) {
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u8, val) }
    }

    pub(super) fn write16(&self, reg: u32, val: u16) {
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u16, val) }
    }

    pub(super) fn read16(&self, reg: u32) -> u16 {
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u16) }
    }

    pub(super) fn write32(&self, reg: u32, val: u32) {
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u32, val) }
    }
}
