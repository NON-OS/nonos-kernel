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

use alloc::collections::VecDeque;
use spin::Mutex;

use super::packet::Packet;

pub const RX_DEPTH: usize = 64;

static RX: Mutex<VecDeque<Packet>> = Mutex::new(VecDeque::new());

pub fn push(packet: Packet) -> bool {
    let mut q = RX.lock();
    if q.len() >= RX_DEPTH {
        return false;
    }
    q.push_back(packet);
    true
}

pub fn pop_any() -> Option<Packet> {
    RX.lock().pop_front()
}

pub fn pop_for_protocol(protocol: u8) -> Option<Packet> {
    let mut q = RX.lock();
    let idx = q.iter().position(|p| p.protocol == protocol)?;
    q.remove(idx)
}
