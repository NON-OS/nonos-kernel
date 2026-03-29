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

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_LITTLE: u8 = 1;
pub const ELF_HEADER_MIN_SIZE: usize = 64;

pub fn validate_elf_header(data: &[u8]) -> bool {
    if data.len() < ELF_HEADER_MIN_SIZE {
        return false;
    }

    if &data[0..4] != &ELF_MAGIC {
        return false;
    }

    if data[4] != ELF_CLASS_64 {
        return false;
    }

    if data[5] != ELF_DATA_LITTLE {
        return false;
    }

    true
}

pub fn get_elf_entry_point(data: &[u8]) -> Option<u64> {
    if !validate_elf_header(data) {
        return None;
    }

    let e_entry = u64::from_le_bytes([
        data[24], data[25], data[26], data[27],
        data[28], data[29], data[30], data[31],
    ]);

    if e_entry == 0 {
        return None;
    }

    Some(e_entry)
}

pub fn get_elf_machine_type(data: &[u8]) -> Option<u16> {
    if data.len() < 20 {
        return None;
    }

    Some(u16::from_le_bytes([data[18], data[19]]))
}

pub fn is_x86_64_elf(data: &[u8]) -> bool {
    const EM_X86_64: u16 = 62;

    match get_elf_machine_type(data) {
        Some(mt) => mt == EM_X86_64,
        None => false,
    }
}
