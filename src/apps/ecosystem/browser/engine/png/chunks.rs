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

pub(super) struct PngHeader {
    pub width: u32,
    pub height: u32,
    pub color_type: u8,
}

pub(super) fn parse_ihdr(data: &[u8]) -> Option<PngHeader> {
    if data.len() < 13 {
        return None;
    }
    let width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let bit_depth = data[8];
    let color_type = data[9];
    let interlace = data[12];
    if bit_depth != 8 || (color_type != 2 && color_type != 6) || interlace != 0 {
        return None;
    }
    if width > 4096 || height > 4096 || width == 0 || height == 0 {
        return None;
    }
    Some(PngHeader { width, height, color_type })
}

pub(super) fn read_chunk(data: &[u8], pos: usize) -> Option<(usize, &[u8], &[u8])> {
    if pos + 8 > data.len() {
        return None;
    }
    let chunk_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    let chunk_type = &data[pos + 4..pos + 8];
    let chunk_data_start = pos + 8;
    let chunk_data_end = chunk_data_start + chunk_len;
    if chunk_data_end > data.len() {
        return None;
    }
    Some((chunk_data_end + 4, chunk_type, &data[chunk_data_start..chunk_data_end]))
}
