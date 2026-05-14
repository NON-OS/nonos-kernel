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

//! Capsule-local state. The L2 capsule's authority is purely IPC;
//! the underlying NIC's claim/grants live in the driver capsule
//! and we never touch them directly. We just remember which NIC
//! port we resolved, our MAC, the local IPv4 we answer ARP for,
//! and the neighbour cache.

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::arp::Cache;
use crate::ethernet::MacAddress;

pub struct State {
    pub nic_port: AtomicU32,
    pub nic_pid: AtomicU32,
    pub mac: Mutex<MacAddress>,
    pub ipv4: Mutex<[u8; 4]>,
    pub arp: Mutex<Cache>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            nic_port: AtomicU32::new(0),
            nic_pid: AtomicU32::new(0),
            mac: Mutex::new([0; 6]),
            ipv4: Mutex::new([0; 4]),
            arp: Mutex::new(Cache::new()),
        }
    }

    pub fn set_nic(&self, port: u32, pid: u32) {
        self.nic_port.store(port, Ordering::Release);
        self.nic_pid.store(pid, Ordering::Release);
    }

    pub fn nic_port(&self) -> u32 {
        self.nic_port.load(Ordering::Acquire)
    }
}

pub static STATE: State = State::new();
