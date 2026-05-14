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

#[derive(Clone, Copy)]
pub struct NamespaceIdentity {
    pub nsid: u32,
    pub size_lba: u64,
    pub capacity_lba: u64,
    pub used_lba: u64,
    pub lba_size: u32,
    pub metadata_size: u16,
    pub format_index: u8,
    pub formatted_lba_count: u8,
}

impl NamespaceIdentity {
    pub const fn absent() -> Self {
        Self {
            nsid: 0,
            size_lba: 0,
            capacity_lba: 0,
            used_lba: 0,
            lba_size: 0,
            metadata_size: 0,
            format_index: 0,
            formatted_lba_count: 0,
        }
    }

    pub fn parse(nsid: u32, data: &[u8]) -> Self {
        let flbas = data[0x1a] & 0x0f;
        let lbaf = 0x80 + (flbas as usize) * 4;
        let metadata = u16::from_le_bytes([data[lbaf], data[lbaf + 1]]);
        let lba_shift = data[lbaf + 2];
        Self {
            nsid,
            size_lba: le64(data, 0x00),
            capacity_lba: le64(data, 0x08),
            used_lba: le64(data, 0x10),
            lba_size: if lba_shift < 32 { 1u32 << lba_shift } else { 0 },
            metadata_size: metadata,
            format_index: flbas,
            formatted_lba_count: data[0x19].saturating_add(1),
        }
    }
}

fn le64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}
