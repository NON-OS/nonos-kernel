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
 * ET_EXEC kernel loading.
 * Fixed-address executables loaded at their specified p_vaddr.
 */

extern crate alloc;

use alloc::format;
use uefi::table::boot::{AllocateType, MemoryType};

use crate::crypto::sig::CapsuleMetadata;
use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::image::KernelImage;
use crate::loader::types::memory;
use crate::log::logger::{log_error, log_info, log_warn};

use super::alloc::{free_all, record_alloc};
use super::constants::{elf_flags, MAX_ALLOCS, PAGE_SIZE};
use super::validate::ValidationResult;

pub fn load_exec_kernel(
    bs: &uefi::table::boot::BootServices,
    payload: &[u8],
    v: &ValidationResult,
) -> LoaderResult<KernelImage> {
    let base = v.min_addr;
    let total_bytes = (v.max_addr - v.min_addr) as usize;
    let pages_needed = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut allocations: [(u64, usize); MAX_ALLOCS] = [(0, 0); MAX_ALLOCS];
    let mut alloc_count: usize = 0;

    let alloc_addr = match bs.allocate_pages(
        AllocateType::Address(base),
        MemoryType::LOADER_DATA,
        pages_needed,
    ) {
        Ok(addr) => {
            record_alloc(&mut allocations, &mut alloc_count, addr, pages_needed)?;
            log_info("loader", &format!("Allocated {} pages at 0x{:x} (ET_EXEC)", pages_needed, addr));
            addr
        }
        Err(e) => {
            log_error("loader", &format!("Allocation failed at 0x{:x}: {:?}", base, e.status()));
            return Err(LoaderError::AllocationFailed { addr: base, pages: pages_needed, status: e.status() });
        }
    };

    load_segments(payload, v, alloc_addr);

    let entry = v.elf.header.e_entry as usize;
    if !(entry >= alloc_addr as usize && entry < alloc_addr as usize + total_bytes) {
        free_all(bs, &allocations, alloc_count);
        log_error("loader", "ELF entry not in loaded segments");
        return Err(LoaderError::EntryNotInRange);
    }

    let image = KernelImage {
        address: alloc_addr as usize,
        size: total_bytes,
        entry_point: entry,
        metadata: CapsuleMetadata {
            offset_sig: 0, len_sig: 0, offset_payload: 0, len_payload: payload.len(),
            signer_keyid: None, payload_hash: [0u8; 32], header_version: 1, header_timestamp: 0,
        },
        allocations: [(0, 0); memory::MAX_ALLOCATIONS],
        alloc_count: 0,
    };

    log_info("loader", &format!("Kernel loaded: 0x{:x} size=0x{:x} entry=0x{:x}", image.address, image.size, image.entry_point));
    Ok(image)
}

fn load_segments(payload: &[u8], v: &ValidationResult, _alloc_addr: u64) {
    for i in 0..v.load_count {
        let seg = &v.loads[i];
        let dst_phys = seg.target as usize;

        if seg.p_align > 1 && (dst_phys & (seg.p_align - 1)) != 0 {
            log_warn("loader", &format!("Segment misaligned at 0x{:x}", dst_phys));
        }

        let rwx = format!(
            "{}{}{}",
            if (seg.p_flags & elf_flags::PF_R) != 0 { "R" } else { "-" },
            if (seg.p_flags & elf_flags::PF_W) != 0 { "W" } else { "-" },
            if (seg.p_flags & elf_flags::PF_X) != 0 { "X" } else { "-" }
        );

        if seg.p_filesz > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr().add(seg.p_offset),
                    dst_phys as *mut u8,
                    seg.p_filesz,
                );
            }
            log_info("loader", &format!("Loaded {} bytes to 0x{:x} [{}]", seg.p_filesz, dst_phys, rwx));
        }

        if seg.p_memsz > seg.p_filesz {
            unsafe {
                core::ptr::write_bytes((dst_phys + seg.p_filesz) as *mut u8, 0, seg.p_memsz - seg.p_filesz);
            }
            log_info("loader", &format!("Zeroed {} bytes at 0x{:x}", seg.p_memsz - seg.p_filesz, dst_phys + seg.p_filesz));
        }
    }
}
