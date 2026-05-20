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
use alloc::vec::Vec;

use crate::crypto::Key;

use super::gateway::Gateway;

pub const RX_DEPTH: usize = 8;

pub struct Session {
    pub owner: u32,
    pub id: u32,
    pub gateway: Gateway,
    pub key: Key,
    rx: VecDeque<Vec<u8>>,
}

impl Session {
    pub fn new(owner: u32, id: u32, gateway: Gateway, key: Key) -> Self {
        Self { owner, id, gateway, key, rx: VecDeque::new() }
    }

    pub fn push(&mut self, body: Vec<u8>) {
        if self.rx.len() == RX_DEPTH {
            let _ = self.rx.pop_front();
        }
        self.rx.push_back(body);
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }
}
