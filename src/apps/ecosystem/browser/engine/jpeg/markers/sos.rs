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

use super::types::{ScanComponent, SosData};
use super::util::read_u16_be;
use alloc::vec::Vec;

pub(super) fn parse_sos(data: &[u8], pos: usize) -> Option<SosData> {
    let length = read_u16_be(data, pos)? as usize;
    if length < 3 || pos + length > data.len() {
        return None;
    }
    let num_components = data[pos + 2] as usize;
    if num_components == 0 || num_components > 4 {
        return None;
    }
    if length < 3 + num_components * 2 + 3 {
        return None;
    }
    let mut components = Vec::with_capacity(num_components);
    for i in 0..num_components {
        let offset = pos + 3 + i * 2;
        let component_id = data[offset];
        let table_sel = data[offset + 1];
        let dc_table_id = (table_sel >> 4) & 0x0F;
        let ac_table_id = table_sel & 0x0F;
        components.push(ScanComponent { component_id, dc_table_id, ac_table_id });
    }
    Some(SosData { components, entropy_data_offset: pos + length })
}
