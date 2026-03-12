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

use super::config::{get_acpi_rsdp, get_framebuffer_info, get_smbios_entry};
use super::jump::{copy_memory_map, finalize_mmap, jump_to_kernel, settle_delay};
pub use super::jump::MemoryMapEntry;
use super::prepare::{
    allocate_handoff_resources, build_handoff_flags, detect_cpu_security_features,
    estimate_tsc_frequency,
};
use super::timing::get_uefi_time_epoch;
use super::types::{
    BootHandoffV1, CryptoHandoff, Measurements, MemoryMap,
    RngSeed, ZkAttestation, HANDOFF_MAGIC, HANDOFF_VERSION,
};
use crate::loader::KernelImage;
use crate::log::logger::log_info;

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
    let allocs = allocate_handoff_resources(&st, cmdline);

    let fb_info = get_framebuffer_info(bs);
    let acpi_rsdp = get_acpi_rsdp(&st);
    let smbios_entry = get_smbios_entry(&st);
    let unix_epoch_ms = get_uefi_time_epoch(&st);
    let tsc_hz = estimate_tsc_frequency(bs);
    let (smep, smap, umip) = detect_cpu_security_features();

    let handoff_flags = build_handoff_flags(
        fb_info.ptr != 0,
        acpi_rsdp != 0,
        &crypto,
        tpm_measured,
        smep,
        smap,
        umip,
    );

    let bh_ptr = allocs.boothandoff_addr as *mut BootHandoffV1;
    unsafe {
        core::ptr::write_bytes(bh_ptr as *mut u8, 0, size_of::<BootHandoffV1>());
        (*bh_ptr).magic = HANDOFF_MAGIC;
        (*bh_ptr).version = HANDOFF_VERSION;
        (*bh_ptr).size = size_of::<BootHandoffV1>() as u16;
        (*bh_ptr).flags = handoff_flags;
        (*bh_ptr).entry_point = kernel.entry_point as u64;
        (*bh_ptr).fb = fb_info;
        (*bh_ptr).mmap = MemoryMap { ptr: 0, entry_size: 0, entry_count: 0, desc_version: 0 };
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
        (*bh_ptr).cmdline_ptr = allocs.cmdline_addr;
        (*bh_ptr).reserved0 = 0;
    }

    crate::display::gop::shutdown_for_exit();
    settle_delay();

    let (_runtime_st, final_mmap) = st.exit_boot_services();

    let (mmap_ptr, entry_size, entry_count) = copy_memory_map(allocs.mmap_addr, &final_mmap);
    finalize_mmap(bh_ptr, mmap_ptr, entry_size, entry_count);

    unsafe {
        jump_to_kernel(
            kernel.entry_point as u64,
            allocs.stack_top as u64,
            allocs.boothandoff_addr,
        );
    }
}
