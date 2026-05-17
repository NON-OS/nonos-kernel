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

pub(super) fn u16_at(body: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([body[off], body[off + 1]])
}

pub(super) fn i16_at(body: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([body[off], body[off + 1]])
}

pub(super) fn u32_at(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}

pub(super) fn u64_at(body: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        body[off],
        body[off + 1],
        body[off + 2],
        body[off + 3],
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
    ])
}

pub(super) fn u128_at(body: &[u8], off: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&body[off..off + 16]);
    u128::from_le_bytes(bytes)
}
