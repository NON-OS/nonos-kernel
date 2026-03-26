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

use super::global::find_rtl8139_device;
use crate::bus::pci::{enable_bus_master, enable_io_space};
use crate::sys::serial;

pub struct Rtl8139 {
    pub(super) io_base: u16,
    pub(super) mac: [u8; 6],
    pub(super) initialized: AtomicBool,
    pub(super) tx_cur: AtomicU32,
    pub(super) rx_offset: AtomicU32,
    pub(super) rx_queue: Mutex<Vec<Vec<u8>>>,
}

impl Rtl8139 {
    pub fn new() -> Option<Self> {
        let dev = find_rtl8139_device()?;

        serial::print(b"[RTL8139] Found at ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::println(b"");

        enable_bus_master(dev.bus, dev.device, dev.function);
        enable_io_space(dev.bus, dev.device, dev.function);

        let io_base = (dev.bar0 & !0x3) as u16;
        if io_base == 0 {
            serial::println(b"[RTL8139] BAR0 is zero!");
            return None;
        }

        serial::print(b"[RTL8139] IO base: 0x");
        serial::print_hex(io_base as u64);
        serial::println(b"");

        Some(Self {
            io_base,
            mac: [0; 6],
            initialized: AtomicBool::new(false),
            tx_cur: AtomicU32::new(0),
            rx_offset: AtomicU32::new(0),
            rx_queue: Mutex::new(Vec::new()),
        })
    }
}
