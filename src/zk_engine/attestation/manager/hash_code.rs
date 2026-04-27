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

use super::types::AttestationManager;
use crate::crypto::hash::blake3_hash;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn hash_kernel_code(_mgr: &AttestationManager) -> Result<[u8; 32], ZKError> {
    let sections = crate::memory::layout::kernel_sections();
    let mut hasher_input = Vec::new();
    for section in sections.iter() {
        if section.rx {
            let start = section.start as *const u8;
            let size = section.size() as usize;
            let mut offset = 0;
            while offset < size {
                let chunk_size = core::cmp::min(4096, size - offset);
                let chunk_ptr = unsafe { start.add(offset) };
                let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
                hasher_input.extend_from_slice(&blake3_hash(chunk));
                offset += chunk_size;
            }
        }
    }
    let slide = crate::memory::layout::get_slide();
    hasher_input.extend_from_slice(&slide.to_le_bytes());
    Ok(blake3_hash(&hasher_input))
}
