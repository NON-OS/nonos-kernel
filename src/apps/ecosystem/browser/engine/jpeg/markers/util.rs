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

pub(super) const MAX_DIMENSION: u32 = 4096;
pub(super) const MARKER_SOI: u8 = 0xD8;
pub(super) const MARKER_SOF0: u8 = 0xC0;
pub(super) const MARKER_SOF2: u8 = 0xC2;
pub(super) const MARKER_DHT: u8 = 0xC4;
pub(super) const MARKER_DQT: u8 = 0xDB;
pub(super) const MARKER_SOS: u8 = 0xDA;
pub(super) const MARKER_EOI: u8 = 0xD9;

pub(super) fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(((data[offset] as u16) << 8) | (data[offset + 1] as u16))
}
