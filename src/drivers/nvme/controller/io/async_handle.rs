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

pub struct AsyncIoHandle {
    cid: u16,
    transfer_size: usize,
    is_write: bool,
    queue_id: u16,
}

impl AsyncIoHandle {
    pub const fn new(cid: u16, transfer_size: usize, is_write: bool, queue_id: u16) -> Self {
        Self { cid, transfer_size, is_write, queue_id }
    }

    pub fn cid(&self) -> u16 {
        self.cid
    }
    pub fn transfer_size(&self) -> usize {
        self.transfer_size
    }
    pub fn is_write(&self) -> bool {
        self.is_write
    }
    pub fn queue_id(&self) -> u16 {
        self.queue_id
    }
}
