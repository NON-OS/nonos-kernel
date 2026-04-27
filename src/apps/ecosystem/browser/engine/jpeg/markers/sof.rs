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

use super::types::{ComponentInfo, SofData};
use super::util::{read_u16_be, MAX_DIMENSION};
use alloc::vec::Vec;

pub(super) fn parse_sof(data: &[u8], pos: usize, is_baseline: bool) -> Option<SofData> {
    let length = read_u16_be(data, pos)? as usize;
    if length < 8 || pos + length > data.len() {
        return None;
    }
    let precision = data[pos + 2];
    let height = read_u16_be(data, pos + 3)? as u32;
    let width = read_u16_be(data, pos + 5)? as u32;
    let num_components = data[pos + 7] as usize;
    if width == 0 || height == 0 {
        return None;
    }
    if width > MAX_DIMENSION || height > MAX_DIMENSION {
        return None;
    }
    if num_components == 0 || num_components > 4 {
        return None;
    }
    if length < 8 + num_components * 3 {
        return None;
    }
    let mut components = Vec::with_capacity(num_components);
    for i in 0..num_components {
        let offset = pos + 8 + i * 3;
        let id = data[offset];
        let sampling = data[offset + 1];
        let h_sampling = sampling >> 4;
        let v_sampling = sampling & 0x0F;
        let quant_table_id = data[offset + 2];
        if h_sampling == 0 || v_sampling == 0 || h_sampling > 4 || v_sampling > 4 {
            return None;
        }
        components.push(ComponentInfo { id, h_sampling, v_sampling, quant_table_id });
    }
    Some(SofData { is_baseline, _precision: precision, width, height, components })
}
