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

use super::types::HuffmanTableData;
use alloc::vec::Vec;

pub(super) fn parse_dht(
    data: &[u8],
    pos: usize,
    length: usize,
    tables: &mut Vec<HuffmanTableData>,
) -> Option<()> {
    let end = pos + length;
    let mut cur = pos + 2;
    while cur < end {
        if cur >= data.len() {
            return None;
        }
        let info = data[cur];
        let class = (info >> 4) & 0x0F;
        let id = info & 0x0F;
        if class > 1 || id > 3 {
            return None;
        }
        cur += 1;
        if cur + 16 > data.len() {
            return None;
        }
        let mut counts = [0u8; 16];
        let mut total: usize = 0;
        for i in 0..16 {
            counts[i] = data[cur + i];
            total += counts[i] as usize;
        }
        cur += 16;
        if cur + total > data.len() {
            return None;
        }
        let symbols = data[cur..cur + total].to_vec();
        cur += total;
        tables.push(HuffmanTableData { class, id, counts, symbols });
    }
    Some(())
}
