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
use super::cleanup::secure_cleanup_before_jump;
use super::gather::gather_system_info;
use super::handoff_init::init_boothandoff;
use super::validate::{validate_and_jump, JumpAddresses};
use crate::handoff::jump::{copy_memory_map, finalize_mmap, settle_delay};
use crate::handoff::prepare::allocate_handoff_resources;
use crate::handoff::types::{BootHandoffV1, CryptoHandoff};
use crate::firmware::FirmwareHandoff;
use crate::loader::KernelImage;

pub fn exit_and_jump(st: SystemTable<Boot>, kernel: &KernelImage, cmdline: Option<&str>, crypto: CryptoHandoff, firmware: FirmwareHandoff, rng_seed: [u8; 32], tpm_measured: bool) -> ! {
    let bs = st.boot_services();
    let allocs = allocate_handoff_resources(&st, cmdline);
    let params = gather_system_info(&st, bs, kernel, &crypto, firmware, tpm_measured, &allocs, rng_seed);
    let bh_ptr = allocs.boothandoff_addr as *mut BootHandoffV1;
    unsafe { init_boothandoff(bh_ptr, &params) };
    crate::display::gop::shutdown_for_exit();
    secure_cleanup_before_jump();
    settle_delay();
    let (_runtime_st, final_mmap) = st.exit_boot_services();
    let (mmap_ptr, entry_size, entry_count) = copy_memory_map(allocs.mmap_addr, &final_mmap);
    finalize_mmap(bh_ptr, mmap_ptr, entry_size, entry_count);
    validate_and_jump(JumpAddresses { entry: kernel.entry_point as u64, stack: allocs.stack_top as u64, handoff: allocs.boothandoff_addr })
}
