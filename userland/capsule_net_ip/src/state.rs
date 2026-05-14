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

//! Interface configuration the capsule carries for the life of the
//! process: MAC, IPv4 address + prefix, default gateway, MTU,
//! upstream L2 endpoint port. Capsule-local — there is no shared
//! kernel surface for these fields.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use spin::Mutex;

use crate::ipv4::Ipv4Addr;

pub struct InterfaceConfig {
    pub mac: spin::Mutex<[u8; 6]>,
    pub ipv4: Mutex<Ipv4Addr>,
    pub prefix: AtomicU16,
    pub gateway: Mutex<Ipv4Addr>,
    pub mtu: AtomicU16,
    pub l2_service_port: AtomicU32,
    pub identification: AtomicU16,
}

impl InterfaceConfig {
    pub const fn new() -> Self {
        Self {
            mac: spin::Mutex::new([0; 6]),
            ipv4: Mutex::new([0; 4]),
            prefix: AtomicU16::new(0),
            gateway: Mutex::new([0; 4]),
            mtu: AtomicU16::new(1500),
            l2_service_port: AtomicU32::new(0),
            identification: AtomicU16::new(1),
        }
    }

    pub fn next_id(&self) -> u16 {
        let v = self.identification.fetch_add(1, Ordering::Relaxed);
        if v == 0 {
            self.identification.fetch_add(1, Ordering::Relaxed)
        } else {
            v
        }
    }
}

pub static IFACE: InterfaceConfig = InterfaceConfig::new();
