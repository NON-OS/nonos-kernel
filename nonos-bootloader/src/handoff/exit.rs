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

use core::mem::size_of;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::runtime::ResetType;
use super::config::{get_acpi_rsdp, get_framebuffer_info, get_smbios_entry};
use super::timing::{get_uefi_time_epoch, read_tsc};
use super::types::{
    flags, BootHandoffV1, CryptoHandoff, KernelEntry, Measurements, MemoryMap, MemoryMapEntry,
    RngSeed, ZkAttestation, HANDOFF_MAGIC, HANDOFF_VERSION,
};
use crate::loader::KernelImage;
use crate::log::logger::{log_error, log_info, log_warn};

fn fatal_alloc_error(st: &SystemTable<Boot>, msg: &str) -> ! {
    log_error("handoff", msg);
    st.runtime_services()
        .reset(ResetType::COLD, Status::OUT_OF_RESOURCES, None);
}

fn detect_cpu_security_features() -> (bool, bool, bool) {
    let cpuid_result = core::arch::x86_64::__cpuid_count(7, 0);
    // EBX bit 7: SMEP (Supervisor Mode Execution Prevention)
    let smep = (cpuid_result.ebx & (1 << 7)) != 0;
    // EBX bit 20: SMAP (Supervisor Mode Access Prevention)
    let smap = (cpuid_result.ebx & (1 << 20)) != 0;
    // ECX bit 2: UMIP (User-Mode Instruction Prevention)
    let umip = (cpuid_result.ecx & (1 << 2)) != 0;

    (smep, smap, umip)
}

fn estimate_tsc_frequency(bs: &uefi::table::boot::BootServices) -> u64 {
    let tsc_start = read_tsc();
    let _ = bs.stall(10_000);
    let tsc_end = read_tsc();
    if tsc_end > tsc_start {
        // 10ms = 10,000us, so multiply by 100 to get Hz
        (tsc_end - tsc_start) * 100
    } else {
        0
    }
}

pub fn exit_and_jump(
    st: SystemTable<Boot>,
    kernel: &KernelImage,
    cmdline: Option<&str>,
    crypto: CryptoHandoff,
    rng_seed: [u8; 32],
    tpm_measured: bool,
) -> ! {
    log_info("handoff", "Preparing allocations before ExitBootServices.");

    let bs = st.boot_services();
    let bh_addr = match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1) {
        Ok(addr) => addr,
        Err(_) => fatal_alloc_error(&st, "Failed to allocate BootHandoff page"),
    };

    let stack_pages: usize = 8;
    let stack_addr =
        match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, stack_pages) {
            Ok(addr) => addr,
            Err(_) => fatal_alloc_error(&st, "Failed to allocate kernel stack"),
        };
    let stack_top = (stack_addr as usize) + (stack_pages * 0x1000);

    let mmap_pages: usize = 4;
    let mmap_buffer_addr =
        match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, mmap_pages) {
            Ok(addr) => addr,
            Err(_) => fatal_alloc_error(&st, "Failed to allocate memory map buffer"),
        };

    let cmdline_addr: u64 = if let Some(s) = cmdline {
        let cmd_bytes = s.as_bytes();
        let cmd_len = cmd_bytes.len() + 1;
        let cmd_pages = (cmd_len + 0xFFF) / 0x1000;
        if let Ok(cmd_addr) =
            bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, cmd_pages)
        {
            // ## SAFETY: cmd_addr points to allocated pages
            unsafe {
                let ptr = cmd_addr as *mut u8;
                core::ptr::copy_nonoverlapping(cmd_bytes.as_ptr(), ptr, cmd_bytes.len());
                core::ptr::write_volatile(ptr.add(cmd_bytes.len()), 0u8);
            }
            cmd_addr
        } else {
            log_warn(
                "handoff",
                "cmdline allocation failed; proceeding without cmdline",
            );
            0
        }
    } else {
        0
    };

    let fb_info = get_framebuffer_info(bs);
    let acpi_rsdp = get_acpi_rsdp(&st);
    let smbios_entry = get_smbios_entry(&st);
    let unix_epoch_ms = get_uefi_time_epoch(&st);
    let tsc_hz = estimate_tsc_frequency(bs);

    let (smep, smap, umip) = detect_cpu_security_features();

    let mut handoff_flags: u64 = 0;

    if fb_info.ptr != 0 {
        handoff_flags |= flags::FB_AVAILABLE;
    }
    if acpi_rsdp != 0 {
        handoff_flags |= flags::ACPI_AVAILABLE;
    }
    if crypto.secure_boot {
        handoff_flags |= flags::SECURE_BOOT;
    }
    if crypto.zk_attested {
        handoff_flags |= flags::ZK_ATTESTED;
    }
    if tpm_measured {
        handoff_flags |= flags::TPM_MEASURED;
    }
    if smep {
        handoff_flags |= flags::SMEP;
    }
    if smap {
        handoff_flags |= flags::SMAP;
    }
    if umip {
        handoff_flags |= flags::UMIP;
    }

    handoff_flags |= flags::WX;
    handoff_flags |= flags::NXE;
    handoff_flags |= flags::IDMAP_PRESERVED;

    let bh_ptr = bh_addr as *mut BootHandoffV1;
    // ## SAFETY: bh_addr points to allocated page
    unsafe {
        core::ptr::write_bytes(bh_ptr as *mut u8, 0, size_of::<BootHandoffV1>());
        (*bh_ptr).magic = HANDOFF_MAGIC;
        (*bh_ptr).version = HANDOFF_VERSION;
        (*bh_ptr).size = size_of::<BootHandoffV1>() as u16;
        (*bh_ptr).flags = handoff_flags;
        (*bh_ptr).entry_point = kernel.entry_point as u64;
        (*bh_ptr).fb = fb_info;
        (*bh_ptr).mmap = MemoryMap {
            ptr: 0,
            entry_size: 0,
            entry_count: 0,
            desc_version: 0,
        };
        (*bh_ptr).acpi.rsdp = acpi_rsdp;
        (*bh_ptr).smbios.entry = smbios_entry;
        (*bh_ptr).modules.ptr = 0;
        (*bh_ptr).modules.count = 0;
        (*bh_ptr).modules.reserved = 0;
        (*bh_ptr).timing.tsc_hz = tsc_hz;
        (*bh_ptr).timing.unix_epoch_ms = unix_epoch_ms;
        (*bh_ptr).meas = Measurements {
            kernel_sha256: crypto.kernel_hash,
            kernel_sig_ok: if crypto.signature_valid { 1 } else { 0 },
            secure_boot: if crypto.secure_boot { 1 } else { 0 },
            zk_attestation_ok: if crypto.zk_attested { 1 } else { 0 },
            reserved: [0u8; 5],
        };
        (*bh_ptr).rng = RngSeed { seed32: rng_seed };
        (*bh_ptr).zk = ZkAttestation {
            verified: if crypto.zk_attested { 1 } else { 0 },
            flags: 0,
            reserved: [0u8; 6],
            program_hash: crypto.zk_program_hash,
            capsule_commitment: crypto.zk_capsule_commitment,
        };
        (*bh_ptr).cmdline_ptr = cmdline_addr;
        (*bh_ptr).reserved0 = 0;
    }

    log_info("handoff", "Calling ExitBootServices...");

    let (_runtime_st, _final_mmap) = st.exit_boot_services();

    // TEMPORARILY DISABLED: Memory map copying crashes after ExitBootServices
    // due to uefi crate's iterator being corrupted. The kernel will discover
    // memory via ACPI instead. Re-enable once uefi crate is fixed.
    //
    // // ## SAFETY: Operating in post-ExitBootServices environment
    // unsafe {
    //     let mmap_buffer = mmap_buffer_addr as *mut MemoryMapEntry;
    //     let max_entries = (mmap_pages * 0x1000) / size_of::<MemoryMapEntry>();
    //
    //     let mut entry_count: u32 = 0;
    //     for (i, desc) in final_mmap.entries().enumerate() {
    //         if i >= max_entries {
    //             break;
    //         }
    //
    //         let entry = mmap_buffer.add(i);
    //         (*entry).memory_type = desc.ty.0;
    //         (*entry).physical_start = desc.phys_start;
    //         (*entry).virtual_start = desc.virt_start;
    //         (*entry).page_count = desc.page_count;
    //         (*entry).attribute = desc.att.bits();
    //
    //         entry_count += 1;
    //     }
    //
    //     (*bh_ptr).mmap.ptr = mmap_buffer_addr;
    //     (*bh_ptr).mmap.entry_size = size_of::<MemoryMapEntry>() as u32;
    //     (*bh_ptr).mmap.entry_count = entry_count;
    //     (*bh_ptr).mmap.desc_version = 1;
    // }

    // Empty memory map, kernel should use ACPI for memory discovery
    unsafe {
        (*bh_ptr).mmap.ptr = 0;
        (*bh_ptr).mmap.entry_size = 0;
        (*bh_ptr).mmap.entry_count = 0;
        (*bh_ptr).mmap.desc_version = 0;
    }

    let boothandoff_ptr = bh_addr;
    let entry_addr = kernel.entry_point as u64;

    // ## SAFETY: Transferring control to kernel
    unsafe {
        // RAX = entry address, RCX = stack, RDI = handoff
        core::arch::asm!(
            // Disable interrupts during transition
            "cli",
            // Set up registers in safe order
            "mov rax, {entry}",     // RAX = kernel entry point
            "mov rcx, {stack}",     // RCX = new stack pointer
            "mov rdi, {handoff}",   // RDI = handoff pointer (kernel first arg)
            // Now set stack and jump
            "mov rsp, rcx",         // Set new stack
            "xor rbp, rbp",         // Clear frame pointer
            "jmp rax",              // Jump to kernel!
            entry = in(reg) entry_addr,
            stack = in(reg) stack_top as u64,
            handoff = in(reg) boothandoff_ptr as u64,
            options(noreturn)
        );
    }
}
