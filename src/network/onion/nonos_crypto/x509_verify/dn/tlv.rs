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

pub(super) fn read_tlv(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset >= data.len() {
        return None;
    }
    let (len, content_start) = read_der_length(data, offset + 1)?;
    let content_end = content_start + len;
    if content_end > data.len() {
        return None;
    }
    Some((&data[content_start..content_end], content_end))
}

pub(super) fn read_tlv_raw(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    read_tlv(data, offset)
}

pub(super) fn unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (len, content_start) = read_der_length(data, 1)?;
    let end = content_start + len;
    if end > data.len() {
        return None;
    }
    Some(&data[content_start..end])
}

fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        Some((first as usize, offset + 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[offset + 1 + i] as usize;
        }
        Some((len, offset + 1 + num_bytes))
    }
}
