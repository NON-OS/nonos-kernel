// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const CIRCUIT_SECTION_MAGIC: [u8; 4] = [b'N', 0xC3, b'Z', b'K'];

#[repr(C)]
pub struct CircuitSectionHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub count: u32,
    pub size: u32,
    pub signature: [u8; 64],
    pub signer: [u8; 32],
}

#[repr(C)]
pub struct CircuitSectionEntry {
    pub program_hash: [u8; 32],
    pub permissions: u32,
    pub category: u8,
    pub name_len: u8,
    pub version_len: u8,
    pub _reserved: u8,
    pub vk_offset: u32,
    pub vk_len: u32,
}
