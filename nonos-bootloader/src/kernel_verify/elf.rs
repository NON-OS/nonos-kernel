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

/*
 * ELF64 header parsing for kernel size computation.
 * Used to determine where kernel code ends and signature begins.
 */

use crate::zk::attest::{GROTH16_PROOF_SIZE, ZK_PROOF_HEADER_SIZE, ZK_PROOF_MAGIC};

pub fn compute_elf_size(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }

    if &data[0..4] != b"\x7fELF" {
        return None;
    }

    /* class = 2 means ELF64 */
    if data[4] != 2 {
        return None;
    }

    /* only little endian supported */
    let little_endian = data[5] == 1;
    if !little_endian {
        return None;
    }

    /* e_shoff (section header offset) at offset 40 */
    let e_shoff = u64::from_le_bytes([
        data[40], data[41], data[42], data[43],
        data[44], data[45], data[46], data[47],
    ]) as usize;

    /* e_shentsize at offset 58 */
    let e_shentsize = u16::from_le_bytes([data[58], data[59]]) as usize;

    /* e_shnum at offset 60 */
    let e_shnum = u16::from_le_bytes([data[60], data[61]]) as usize;

    let elf_end = e_shoff.checked_add(e_shentsize.checked_mul(e_shnum)?)?;

    if elf_end > data.len() || elf_end < 64 {
        return None;
    }

    Some(elf_end)
}

pub fn find_zk_block_offset(kernel_data: &[u8]) -> Option<usize> {
    let min_zk_size = ZK_PROOF_HEADER_SIZE + GROTH16_PROOF_SIZE;

    if kernel_data.len() < 64 + min_zk_size {
        return None;
    }

    /* search backwards in last 4KB for ZK magic */
    let search_start = kernel_data.len().saturating_sub(4096);
    for i in (search_start..kernel_data.len().saturating_sub(min_zk_size)).rev() {
        if kernel_data.len() - i >= 4 && &kernel_data[i..i + 4] == &ZK_PROOF_MAGIC {
            return Some(i);
        }
    }

    None
}
