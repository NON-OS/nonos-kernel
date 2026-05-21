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

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use spin::Mutex;

static IP_PORT: AtomicU32 = AtomicU32::new(0);
static EPHEMERAL: AtomicU16 = AtomicU16::new(49152);
static LOCAL_IP: Mutex<[u8; 4]> = Mutex::new([0; 4]);

pub fn set_ip_port(port: u32) {
    IP_PORT.store(port, Ordering::Release);
}

pub fn ip_port() -> u32 {
    IP_PORT.load(Ordering::Acquire)
}

pub fn set_local_ip(ip: [u8; 4]) {
    *LOCAL_IP.lock() = ip;
}

pub fn local_ip() -> [u8; 4] {
    *LOCAL_IP.lock()
}

pub fn next_ephemeral() -> u16 {
    let p = EPHEMERAL.fetch_add(1, Ordering::AcqRel);
    if p < 49152 {
        49152
    } else {
        p
    }
}
