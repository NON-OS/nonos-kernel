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

use crate::constants::queue::{BUFFER_SIZE, TX_DESC_COUNT};

#[derive(Clone, Copy)]
pub struct TxRing {
    pub desc_va: u64,
    pub buf_va: u64,
    pub desc_da: u64,
    pub buf_da: u64,
    pub cur: usize,
}

impl TxRing {
    pub const fn new(desc_va: u64, buf_va: u64, desc_da: u64, buf_da: u64) -> Self {
        Self { desc_va, buf_va, desc_da, buf_da, cur: 0 }
    }

    pub fn buffer_va(&self, idx: usize) -> u64 {
        self.buf_va + (idx % TX_DESC_COUNT) as u64 * BUFFER_SIZE as u64
    }

    pub fn buffer_da(&self, idx: usize) -> u64 {
        self.buf_da + (idx % TX_DESC_COUNT) as u64 * BUFFER_SIZE as u64
    }
}
