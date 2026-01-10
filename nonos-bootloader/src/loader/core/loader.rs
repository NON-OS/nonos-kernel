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

#![no_std]

extern crate alloc;

use alloc::format;
use crate::log::logger::{log_error, log_info, log_warn, log_debug};
use crate::crypto::sig::CapsuleMetadata;
use crate::verify::load_validated_capsule;
use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::image::KernelImage;
use crate::loader::types::memory;
use goblin::elf::{header, program_header, Elf};
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType};

const PAGE_SIZE: usize = 0x1000;
const MAX_LOADS: usize = 32;
const MAX_ALLOCS: usize = 64;

mod elf_flags {
    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;
}

fn record_alloc(
    table: &mut [(u64, usize); MAX_ALLOCS],
    count: &mut usize,
    addr: u64,
    pages: usize,
) -> LoaderResult<()> {
    if *count >= MAX_ALLOCS {
        return Err(LoaderError::AllocationTableFull);
    }
    table[*count] = (addr, pages);
    *count += 1;
    Ok(())
}

fn free_all(bs: &uefi::table::boot::BootServices, table: &[(u64, usize); MAX_ALLOCS], count: usize) {
    for i in 0..count {
        let (addr, pages) = table[i];
        if addr == 0 || pages == 0 {
            continue;
        }
        match bs.free_pages(addr, pages) {
            Ok(_) => log_info("loader", &format!("Freed pages at 0x{:x} ({} pages)", addr, pages)),
            Err(e) => log_error(
                "loader",
                &format!("free_pages failed for 0x{:x} ({}): {:?}", addr, pages, e.status()),
            ),
        }
    }
}

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
    log_info("loader", "Parsing ELF binary...");

    let elf = Elf::parse(payload).map_err(|e| {
        log_error("loader", &format!("ELF parse failed: {:?}", e));
        LoaderError::ElfParseError("goblin parse error")
    })?;

    log_info("loader", "ELF parsed successfully");

    if !elf.is_64 {
        log_error("loader", "ELF is not 64-bit.");
        return Err(LoaderError::UnsupportedElf("not 64-bit"));
    }
    if elf.header.e_machine != header::EM_X86_64 {
        log_error("loader", "ELF machine is not x86_64.");
        return Err(LoaderError::UnsupportedElf("non-x86_64"));
    }

    let is_exec = elf.header.e_type == header::ET_EXEC;
    let is_dyn = elf.header.e_type == header::ET_DYN;
    if !is_exec && !is_dyn {
        log_error("loader", "Unsupported ELF type.");
        return Err(LoaderError::UnsupportedElf("unsupported e_type"));
    }

    log_info(
        "loader",
        &format!("ELF type: {}", if is_exec { "ET_EXEC" } else { "ET_DYN" }),
    );

    let bs = system_table.boot_services();

    let mut loads: [(usize, usize, usize, u64, usize, u32); MAX_LOADS] = [(0, 0, 0, 0, 0, 0); MAX_LOADS];
    let mut load_count: usize = 0;
    let mut min_addr: Option<u64> = None;
    let mut max_addr: Option<u64> = None;

    for ph in &elf.program_headers {
        if ph.p_type != program_header::PT_LOAD {
            continue;
        }
        if load_count >= MAX_LOADS {
            log_error("loader", "too many PT_LOADs for fixed table");
            return Err(LoaderError::AllocationTableFull);
        }

        let p_offset = ph.p_offset as usize;
        let p_filesz = ph.p_filesz as usize;
        let p_memsz = ph.p_memsz as usize;
        let p_flags = ph.p_flags;

        if p_memsz < p_filesz {
            log_error("loader", "SECURITY: Segment has p_memsz < p_filesz (malformed ELF)");
            return Err(LoaderError::InvalidSegmentSize);
        }

        let file_end = p_offset.checked_add(p_filesz).ok_or_else(|| {
            log_error("loader", "SECURITY: Integer overflow in segment offset+size");
            LoaderError::IntegerOverflow
        })?;

        if file_end > payload.len() {
            log_error("loader", "ELF program header indicates file data outside payload bounds.");
            return Err(LoaderError::SegmentOutOfBounds);
        }

        let is_writable = (p_flags & elf_flags::PF_W) != 0;
        let is_executable = (p_flags & elf_flags::PF_X) != 0;
        if is_writable && is_executable {
            log_warn("loader", "WARNING: Segment has W+X permissions (W^X violation)");
        }

        let target = if ph.p_paddr != 0 { ph.p_paddr } else { ph.p_vaddr } as u64;
        if target == 0 {
            log_error("loader", "PT_LOAD has no placement address.");
            return Err(LoaderError::UnsupportedElf("no placement address"));
        }

        if target < memory::MIN_LOAD_ADDRESS {
            log_error("loader", "SECURITY: Load address too low (below 1MB)");
            return Err(LoaderError::AddressOutOfRange);
        }

        let base_page = target & !((PAGE_SIZE as u64) - 1);
        let offset_into_page = (target - base_page) as usize;
        let seg_start = base_page + (offset_into_page as u64);

        let seg_end = seg_start.checked_add(p_memsz as u64).ok_or_else(|| {
            log_error("loader", "SECURITY: Integer overflow computing segment end");
            LoaderError::IntegerOverflow
        })?;

        if seg_end > memory::MAX_LOAD_ADDRESS {
            log_error("loader", "SECURITY: Segment extends beyond maximum load address");
            return Err(LoaderError::AddressOutOfRange);
        }

        min_addr = Some(min_addr.map_or(seg_start, |m| m.min(seg_start)));
        max_addr = Some(max_addr.map_or(seg_end, |m| m.max(seg_end)));

        loads[load_count] = (p_offset, p_filesz, p_memsz, target, ph.p_align as usize, p_flags);
        load_count += 1;

        log_debug("loader", "Validated PT_LOAD segment");
    }

    if load_count == 0 {
        log_error("loader", "No PT_LOAD segments found in ELF payload.");
        return Err(LoaderError::NoLoadableSegments);
    }

    let base = min_addr.ok_or_else(|| {
        log_error("loader", "Internal error: min_addr not set after segment processing");
        LoaderError::MalformedElf("min_addr computation failed")
    })?;
    let end = max_addr.ok_or_else(|| {
        log_error("loader", "Internal error: max_addr not set after segment processing");
        LoaderError::MalformedElf("max_addr computation failed")
    })?;

    let total_bytes = end.checked_sub(base).ok_or_else(|| {
        log_error("loader", "SECURITY: Size calculation underflow");
        LoaderError::IntegerOverflow
    })? as usize;

    if total_bytes > memory::MAX_KERNEL_SIZE {
        log_error("loader", "SECURITY: Kernel size exceeds maximum allowed (256 MiB)");
        return Err(LoaderError::KernelTooLarge);
    }

    if total_bytes == 0 {
        log_error("loader", "SECURITY: Kernel has zero size");
        return Err(LoaderError::MalformedElf("zero size kernel"));
    }

    let pages_needed = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    log_info("loader", "Kernel size validated");

    let mut allocations: [(u64, usize); MAX_ALLOCS] = [(0, 0); MAX_ALLOCS];
    let mut alloc_count: usize = 0;

    if is_exec {
        let alloc_addr = match bs.allocate_pages(
            AllocateType::Address(base),
            MemoryType::LOADER_DATA,
            pages_needed,
        ) {
            Ok(addr) => {
                record_alloc(&mut allocations, &mut alloc_count, addr, pages_needed)?;
                log_info(
                    "loader",
                    &format!("Allocated {} pages at 0x{:x} for kernel (ET_EXEC)", pages_needed, addr),
                );
                addr
            }
            Err(e) => {
                log_error(
                    "loader",
                    &format!("Failed to allocate {} pages at 0x{:x}: {:?}", pages_needed, base, e.status()),
                );
                return Err(LoaderError::AllocationFailed {
                    addr: base,
                    pages: pages_needed,
                    status: e.status(),
                });
            }
        };

        for i in 0..load_count {
            let (p_offset, p_filesz, p_memsz, target, _align, _flags) = loads[i];
            let dst_phys = target as usize;
            if p_filesz > 0 {
                // SAFETY: We've validated segment bounds and allocated sufficient memory
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        payload.as_ptr().add(p_offset),
                        dst_phys as *mut u8,
                        p_filesz,
                    );
                }
                log_info("loader", &format!("Copied {} bytes to 0x{:x}", p_filesz, dst_phys));
            }

            if p_memsz > p_filesz {
                // SAFETY: Zero-initialize BSS region
                unsafe {
                    core::ptr::write_bytes((dst_phys + p_filesz) as *mut u8, 0, p_memsz - p_filesz);
                }
                log_info(
                    "loader",
                    &format!("Zeroed {} bytes at 0x{:x}", p_memsz - p_filesz, dst_phys + p_filesz),
                );
            }
        }

        let entry = elf.header.e_entry as usize;
        if !(entry >= base as usize && entry < base as usize + total_bytes) {
            free_all(bs, &allocations, alloc_count);
            log_error("loader", "ELF entry not contained within loaded segments.");
            return Err(LoaderError::EntryNotInRange);
        }

        let k = KernelImage {
            address: base as usize,
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
            &format!("Kernel loaded: base=0x{:x} size=0x{:x} entry=0x{:x}", k.address, k.size, k.entry_point),
        );
        return Ok(k);
    }

    {
        let alloc_addr = match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages_needed) {
            Ok(addr) => {
                record_alloc(&mut allocations, &mut alloc_count, addr, pages_needed)?;
                log_info(
                    "loader",
                    &format!("Allocated {} pages at 0x{:x} for ET_DYN image", pages_needed, addr),
                );
                addr
            }
            Err(e) => {
                log_error("loader", &format!("ET_DYN allocation failed: {:?}", e.status()));
                return Err(LoaderError::AllocationFailed {
                    addr: 0,
                    pages: pages_needed,
                    status: e.status(),
                });
            }
        };

        let base_phys = alloc_addr as u64;

        for i in 0..load_count {
            let (p_offset, p_filesz, p_memsz, target, _align, _flags) = loads[i];
            let rel = (target as u64).wrapping_sub(base);
            let dst = (base_phys + rel) as usize;
            if p_filesz > 0 {
                // SAFETY: We've validated segment bounds and allocated sufficient memory
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        payload.as_ptr().add(p_offset),
                        dst as *mut u8,
                        p_filesz,
                    );
                }
            }
            if p_memsz > p_filesz {
                // SAFETY: Zero-initialize BSS region
                unsafe {
                    core::ptr::write_bytes((dst + p_filesz) as *mut u8, 0, p_memsz - p_filesz);
                }
            }
        }

        let load_bias = (base_phys as i64) - (base as i64);
        match crate::loader::reloc::process_elf_relocations(&elf, base_phys, load_bias, payload) {
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

        let entry_rel = elf.header.e_entry as u64;
        let entry_phys = (base_phys as usize).checked_add(entry_rel as usize).ok_or(
            LoaderError::UefiError {
                desc: "entry overflow",
                status: Status::OUT_OF_RESOURCES,
            },
        )?;

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
        return Ok(image);
    }
}
