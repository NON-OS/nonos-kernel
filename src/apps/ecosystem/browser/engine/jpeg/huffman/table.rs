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

use crate::apps::ecosystem::browser::engine::jpeg::markers::HuffmanTableData;
use alloc::vec::Vec;

pub(crate) const MAX_CODE_LEN: usize = 16;

#[derive(Debug, Clone)]
pub(super) struct HuffmanTable {
    pub(super) min_code: [i32; MAX_CODE_LEN],
    pub(super) max_code: [i32; MAX_CODE_LEN],
    pub(super) val_ptr: [usize; MAX_CODE_LEN],
    pub(super) symbols: Vec<u8>,
}

impl HuffmanTable {
    pub(super) fn from_dht(dht: &HuffmanTableData) -> Option<Self> {
        let mut symbols = Vec::with_capacity(dht.symbols.len());
        symbols.extend_from_slice(&dht.symbols);

        let mut min_code = [0i32; MAX_CODE_LEN];
        let mut max_code = [-1i32; MAX_CODE_LEN];
        let mut val_ptr = [0usize; MAX_CODE_LEN];

        let mut code: i32 = 0;
        let mut si = 0usize;

        for i in 0..MAX_CODE_LEN {
            let count = dht.counts[i] as usize;
            if count > 0 {
                val_ptr[i] = si;
                min_code[i] = code;
                max_code[i] = code + count as i32 - 1;
                si += count;
                code += count as i32;
            }
            code <<= 1;
        }

        Some(HuffmanTable { min_code, max_code, val_ptr, symbols })
    }
}
