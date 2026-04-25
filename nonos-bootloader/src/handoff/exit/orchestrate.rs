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

use uefi::prelude::*;

use super::handoff_init::{init_boothandoff, HandoffInitParams};
use super::validate::{validate_and_jump, JumpAddresses};
use super::super::config::{get_acpi_rsdp, get_framebuffer_info, get_smbios_entry};
use super::super::jump::{copy_memory_map, finalize_mmap, settle_delay};
use super::super::prepare::{
    allocate_handoff_resources, build_handoff_flags, detect_cpu_security_features,
    estimate_tsc_frequency,
};
use super::super::timing::get_uefi_time_epoch;
use super::super::types::{BootHandoffV1, CryptoHandoff};
use crate::firmware::FirmwareHandoff;
use crate::loader::KernelImage;
use crate::log::logger::log_info;

pub fn exit_and_jump(
    st: SystemTable<Boot>,
    kernel: &KernelImage,
    cmdline: Option<&str>,
    crypto: CryptoHandoff,
    firmware: FirmwareHandoff,
    rng_seed: [u8; 32],
    tpm_measured: bool,
) -> ! {
    log_info("handoff", "Preparing allocations before ExitBootServices.");

    let bs = st.boot_services();
    let allocs = allocate_handoff_resources(&st, cmdline);
    let params = gather_system_info(&st, bs, kernel, &crypto, firmware, tpm_measured, &allocs, rng_seed);
    let bh_ptr = allocs.boothandoff_addr as *mut BootHandoffV1;

    unsafe { init_boothandoff(bh_ptr, &params) };

    crate::display::gop::shutdown_for_exit();
    settle_delay();

    let (_runtime_st, final_mmap) = st.exit_boot_services();
    let (mmap_ptr, entry_size, entry_count) = copy_memory_map(allocs.mmap_addr, &final_mmap);
    finalize_mmap(bh_ptr, mmap_ptr, entry_size, entry_count);

    validate_and_jump(JumpAddresses {
        entry: kernel.entry_point as u64,
        stack: allocs.stack_top as u64,
        handoff: allocs.boothandoff_addr,
    })
}

fn gather_system_info(
    st: &SystemTable<Boot>,
    bs: &BootServices,
    kernel: &KernelImage,
    crypto: &CryptoHandoff,
    firmware: FirmwareHandoff,
    tmp_measured: bool,
    allocs: &super::super::prepare::HandoffAllocations,
    rng_seed: [u8; 32],
) -> HandoffInitParams {
    let fb_info = get_framebuffer_info(bs);
    let (smep, smap, umip) = detect_cpu_security_features();
    let acpi_rsdp = get_acpi_rsdp(st);

    HandoffInitParams {
        fb_info,
        acpi_rsdp,
        smbios_entry: get_smbios_entry(st),
        unix_epoch_ms: get_uefi_time_epoch(st),
        tsc_hz: estimate_tsc_frequency(bs),
        handoff_flags: build_handoff_flags(
            fb_info.ptr != 0, acpi_rsdp != 0, crypto, tmp_measured, smep, smap, umip,
        ),
        entry_point: kernel.entry_point as u64,
        cmdline_addr: allocs.cmdline_addr,
        crypto: *crypto,
        firmware,
        rng_seed,
    }
}
