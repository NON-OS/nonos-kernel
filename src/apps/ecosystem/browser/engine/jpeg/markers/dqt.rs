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

use super::types::QuantTable;
use super::util::read_u16_be;
use alloc::vec::Vec;

pub(super) fn parse_dqt(
    data: &[u8],
    pos: usize,
    length: usize,
    tables: &mut Vec<QuantTable>,
) -> Option<()> {
    let end = pos + length;
    let mut cur = pos + 2;
    while cur < end {
        if cur >= data.len() {
            return None;
        }
        let info = data[cur];
        let precision = (info >> 4) & 0x0F;
        let id = info & 0x0F;
        if id > 3 {
            return None;
        }
        cur += 1;
        let mut values = [0u16; 64];
        if precision == 0 {
            if cur + 64 > data.len() {
                return None;
            }
            for i in 0..64 {
                values[i] = data[cur + i] as u16;
            }
            cur += 64;
        } else {
            if cur + 128 > data.len() {
                return None;
            }
            for i in 0..64 {
                values[i] = read_u16_be(data, cur + i * 2)?;
            }
            cur += 128;
        }
        tables.push(QuantTable { id, values });
    }
    Some(())
}
