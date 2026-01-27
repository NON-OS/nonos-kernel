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

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::types::memory;
use crate::log::logger::{log_debug, log_error, log_info, log_warn};
use alloc::format;
use goblin::elf::{header, program_header, Elf};

use super::constants::{elf_flags, MAX_LOADS, PAGE_SIZE};

pub struct ValidatedSegment {
    pub p_offset: usize,
    pub p_filesz: usize,
    pub p_memsz: usize,
    pub target: u64,
    pub p_align: usize,
    pub p_flags: u32,
}

pub struct ValidationResult<'a> {
    pub elf: Elf<'a>,
    pub loads: [ValidatedSegment; MAX_LOADS],
    pub load_count: usize,
    pub min_addr: u64,
    pub max_addr: u64,
    pub is_exec: bool,
    pub is_dyn: bool,
}

impl Default for ValidatedSegment {
    fn default() -> Self {
        Self {
            p_offset: 0,
            p_filesz: 0,
            p_memsz: 0,
            target: 0,
            p_align: 0,
            p_flags: 0,
        }
    }
}

pub fn validate_elf(payload: &[u8]) -> LoaderResult<ValidationResult<'_>> {
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

    let mut loads: [ValidatedSegment; MAX_LOADS] =
        core::array::from_fn(|_| ValidatedSegment::default());
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
            log_error(
                "loader",
                "SECURITY: Segment has p_memsz < p_filesz (malformed ELF)",
            );
            return Err(LoaderError::InvalidSegmentSize);
        }

        let file_end = p_offset.checked_add(p_filesz).ok_or_else(|| {
            log_error(
                "loader",
                "SECURITY: Integer overflow in segment offset+size",
            );
            LoaderError::IntegerOverflow
        })?;

        if file_end > payload.len() {
            log_error(
                "loader",
                "ELF program header indicates file data outside payload bounds.",
            );
            return Err(LoaderError::SegmentOutOfBounds);
        }

        let is_writable = (p_flags & elf_flags::PF_W) != 0;
        let is_executable = (p_flags & elf_flags::PF_X) != 0;
        if is_writable && is_executable {
            log_warn(
                "loader",
                "WARNING: Segment has W+X permissions (W^X violation)",
            );
        }

        let target = if ph.p_paddr != 0 {
            ph.p_paddr
        } else {
            ph.p_vaddr
        } as u64;
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
            log_error(
                "loader",
                "SECURITY: Segment extends beyond maximum load address",
            );
            return Err(LoaderError::AddressOutOfRange);
        }

        min_addr = Some(min_addr.map_or(seg_start, |m| m.min(seg_start)));
        max_addr = Some(max_addr.map_or(seg_end, |m| m.max(seg_end)));

        loads[load_count] = ValidatedSegment {
            p_offset,
            p_filesz,
            p_memsz,
            target,
            p_align: ph.p_align as usize,
            p_flags,
        };
        load_count += 1;

        log_debug("loader", "Validated PT_LOAD segment");
    }

    if load_count == 0 {
        log_error("loader", "No PT_LOAD segments found in ELF payload.");
        return Err(LoaderError::NoLoadableSegments);
    }

    let base = min_addr.ok_or_else(|| {
        log_error(
            "loader",
            "Internal error: min_addr not set after segment processing",
        );
        LoaderError::MalformedElf("min_addr computation failed")
    })?;
    let end = max_addr.ok_or_else(|| {
        log_error(
            "loader",
            "Internal error: max_addr not set after segment processing",
        );
        LoaderError::MalformedElf("max_addr computation failed")
    })?;

    let total_bytes = end.checked_sub(base).ok_or_else(|| {
        log_error("loader", "SECURITY: Size calculation underflow");
        LoaderError::IntegerOverflow
    })? as usize;

    if total_bytes > memory::MAX_KERNEL_SIZE {
        log_error(
            "loader",
            "SECURITY: Kernel size exceeds maximum allowed (256 MiB)",
        );
        return Err(LoaderError::KernelTooLarge);
    }

    if total_bytes == 0 {
        log_error("loader", "SECURITY: Kernel has zero size");
        return Err(LoaderError::MalformedElf("zero size kernel"));
    }

    log_info("loader", "Kernel size validated");
    Ok(ValidationResult {
        elf,
        loads,
        load_count,
        min_addr: base,
        max_addr: end,
        is_exec,
        is_dyn,
    })
}
