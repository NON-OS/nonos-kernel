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

extern crate alloc;

use crate::crypto::sig::CapsuleMetadata;
use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::image::KernelImage;
use crate::loader::types::memory;
use crate::log::logger::{log_error, log_info, log_warn};
use crate::verify::load_validated_capsule;
use alloc::format;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType};

use super::alloc::{free_all, record_alloc};
use super::constants::{elf_flags, MAX_ALLOCS, PAGE_SIZE};
use super::validate::{validate_elf, ValidationResult};

pub fn load_kernel(
    system_table: &mut SystemTable<Boot>,
    capsule_bytes: &[u8],
) -> LoaderResult<KernelImage> {
    log_info("loader", "Starting kernel load operation.");

    let payload: &[u8] = match load_validated_capsule(capsule_bytes) {
        Some(validated) => {
            log_info("loader", "Capsule validated successfully");
            return load_kernel_internal(system_table, &validated);
        }
        None => {
            log_info("loader", "No capsule format detected, loading as raw ELF");
            capsule_bytes
        }
    };

    load_kernel_internal(system_table, payload)
}

fn load_kernel_internal(
    system_table: &mut SystemTable<Boot>,
    payload: &[u8],
) -> LoaderResult<KernelImage> {
    let validation = validate_elf(payload)?;
    let bs = system_table.boot_services();
    if validation.is_exec {
        load_exec_kernel(bs, payload, &validation)
    } else if validation.is_dyn {
        load_dyn_kernel(bs, payload, &validation)
    } else {
        log_error("loader", "ELF is neither ET_EXEC nor ET_DYN");
        Err(LoaderError::UnsupportedElf("unsupported ELF type"))
    }
}

fn load_exec_kernel(
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
            log_info(
                "loader",
                &format!(
                    "Allocated {} pages at 0x{:x} for kernel (ET_EXEC)",
                    pages_needed, addr
                ),
            );
            addr
        }
        Err(e) => {
            log_error(
                "loader",
                &format!(
                    "Failed to allocate {} pages at 0x{:x}: {:?}",
                    pages_needed,
                    base,
                    e.status()
                ),
            );
            return Err(LoaderError::AllocationFailed {
                addr: base,
                pages: pages_needed,
                status: e.status(),
            });
        }
    };

    for i in 0..v.load_count {
        let seg = &v.loads[i];
        let dst_phys = seg.target as usize;

        // Verify segment alignment (p_align must be a power of 2)
        if seg.p_align > 1 && (dst_phys & (seg.p_align - 1)) != 0 {
            log_warn(
                "loader",
                &format!(
                    "Segment at 0x{:x} misaligned (p_align=0x{:x})",
                    dst_phys, seg.p_align
                ),
            );
        }

        // Log segment permissions for security auditing
        let rwx = format!(
            "{}{}{}",
            if (seg.p_flags & elf_flags::PF_R) != 0 { "R" } else { "-" },
            if (seg.p_flags & elf_flags::PF_W) != 0 { "W" } else { "-" },
            if (seg.p_flags & elf_flags::PF_X) != 0 { "X" } else { "-" }
        );

        if seg.p_filesz > 0 {
            // SAFETY: We've validated segment bounds and allocated sufficient memory
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr().add(seg.p_offset),
                    dst_phys as *mut u8,
                    seg.p_filesz,
                );
            }
            log_info(
                "loader",
                &format!(
                    "Loaded {} bytes to 0x{:x} [{}]",
                    seg.p_filesz, dst_phys, rwx
                ),
            );
        }

        if seg.p_memsz > seg.p_filesz {
            // SAFETY: Zero-initialize BSS region
            unsafe {
                core::ptr::write_bytes(
                    (dst_phys + seg.p_filesz) as *mut u8,
                    0,
                    seg.p_memsz - seg.p_filesz,
                );
            }
            log_info(
                "loader",
                &format!(
                    "Zeroed {} bytes at 0x{:x}",
                    seg.p_memsz - seg.p_filesz,
                    dst_phys + seg.p_filesz
                ),
            );
        }
    }

    let entry = v.elf.header.e_entry as usize;
    if !(entry >= alloc_addr as usize && entry < alloc_addr as usize + total_bytes) {
        free_all(bs, &allocations, alloc_count);
        log_error("loader", "ELF entry not contained within loaded segments.");
        return Err(LoaderError::EntryNotInRange);
    }

    let k = KernelImage {
        address: alloc_addr as usize,
        size: total_bytes,
        entry_point: entry,
        metadata: CapsuleMetadata {
            offset_sig: 0,
            len_sig: 0,
            offset_payload: 0,
            len_payload: payload.len(),
            signer_keyid: None,
            payload_hash: [0u8; 32],
            header_version: 1,
            header_timestamp: 0,
        },
        allocations: [(0, 0); memory::MAX_ALLOCATIONS],
        alloc_count: 0,
    };
    log_info(
        "loader",
        &format!(
            "Kernel loaded: base=0x{:x} size=0x{:x} entry=0x{:x}",
            k.address, k.size, k.entry_point
        ),
    );
    Ok(k)
}

fn load_dyn_kernel(
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
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        pages_needed,
    ) {
        Ok(addr) => {
            record_alloc(&mut allocations, &mut alloc_count, addr, pages_needed)?;
            log_info(
                "loader",
                &format!(
                    "Allocated {} pages at 0x{:x} for ET_DYN image",
                    pages_needed, addr
                ),
            );
            addr
        }
        Err(e) => {
            log_error(
                "loader",
                &format!("ET_DYN allocation failed: {:?}", e.status()),
            );
            return Err(LoaderError::AllocationFailed {
                addr: 0,
                pages: pages_needed,
                status: e.status(),
            });
        }
    };

    let base_phys = alloc_addr as u64;

    for i in 0..v.load_count {
        let seg = &v.loads[i];
        let rel = (seg.target as u64).wrapping_sub(base);
        let dst = (base_phys + rel) as usize;
        if seg.p_filesz > 0 {
            // SAFETY: We've validated segment bounds and allocated sufficient memory
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr().add(seg.p_offset),
                    dst as *mut u8,
                    seg.p_filesz,
                );
            }
        }
        if seg.p_memsz > seg.p_filesz {
            // SAFETY: Zero-initialize BSS region
            unsafe {
                core::ptr::write_bytes(
                    (dst + seg.p_filesz) as *mut u8,
                    0,
                    seg.p_memsz - seg.p_filesz,
                );
            }
        }
    }

    let load_bias = (base_phys as i64) - (base as i64);
    match crate::loader::reloc::process_elf_relocations(&v.elf, base_phys, load_bias, payload) {
        Ok(reloc_count) => {
            if reloc_count > 0 {
                log_info(
                    "loader",
                    &format!("Applied {} relocations for ET_DYN image", reloc_count),
                );
            }
        }
        Err(e) => {
            log_warn("loader", &format!("Relocation processing warning: {}", e));
        }
    }

    let entry_rel = v.elf.header.e_entry as u64;
    let entry_phys =
        (base_phys as usize)
            .checked_add(entry_rel as usize)
            .ok_or(LoaderError::UefiError {
                desc: "entry overflow",
                status: Status::OUT_OF_RESOURCES,
            })?;

    let image = KernelImage {
        address: base_phys as usize,
        size: pages_needed * PAGE_SIZE,
        entry_point: entry_phys,
        metadata: CapsuleMetadata {
            offset_sig: 0,
            len_sig: 0,
            offset_payload: 0,
            len_payload: payload.len(),
            signer_keyid: None,
            payload_hash: [0u8; 32],
            header_version: 1,
            header_timestamp: 0,
        },
        allocations: [(0, 0); memory::MAX_ALLOCATIONS],
        alloc_count: 0,
    };
    log_info(
        "loader",
        &format!(
            "ET_DYN kernel loaded at 0x{:x} size=0x{:x} entry=0x{:x}",
            image.address, image.size, image.entry_point
        ),
    );
    Ok(image)
}
