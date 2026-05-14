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

use crate::ip_client::UdpInbound;

pub const RX_RING_DEPTH: usize = 32;

pub struct BindEntry {
    pub owner_pid: u32,
    pub port: u16,
    pub rx: VecDeque<UdpInbound>,
}

impl BindEntry {
    pub fn new(owner_pid: u32, port: u16) -> Self {
        Self { owner_pid, port, rx: VecDeque::with_capacity(RX_RING_DEPTH) }
    }

    pub fn push(&mut self, seg: UdpInbound) -> bool {
        if self.rx.len() >= RX_RING_DEPTH {
            return false;
        }
        self.rx.push_back(seg);
        true
    }

    pub fn pop(&mut self) -> Option<UdpInbound> {
        self.rx.pop_front()
    }
}
