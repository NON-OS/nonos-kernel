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

use crate::firmware::FirmwareHandoff;
use super::super::types::{
    BootHandoffV1, CryptoHandoff, FramebufferInfo, Measurements, MemoryMap,
    RngSeed, ZkAttestation, HANDOFF_MAGIC, HANDOFF_VERSION,
};

pub struct HandoffInitParams {
    pub fb_info: FramebufferInfo,
    pub acpi_rsdp: u64,
    pub smbios_entry: u64,
    pub unix_epoch_ms: u64,
    pub tsc_hz: u64,
    pub handoff_flags: u64,
    pub entry_point: u64,
    pub cmdline_addr: u64,
    pub crypto: CryptoHandoff,
    pub firmware: FirmwareHandoff,
    pub rng_seed: [u8; 32],
}

pub unsafe fn init_boothandoff(bh_ptr: *mut BootHandoffV1, params: &HandoffInitParams) {
    core::ptr::write_bytes(bh_ptr as *mut u8, 0, size_of::<BootHandoffV1>());
    (*bh_ptr).magic = HANDOFF_MAGIC;
    (*bh_ptr).version = HANDOFF_VERSION;
    (*bh_ptr).size = size_of::<BootHandoffV1>() as u16;
    (*bh_ptr).flags = params.handoff_flags;
    (*bh_ptr).entry_point = params.entry_point;
    (*bh_ptr).fb = params.fb_info;
    (*bh_ptr).mmap = MemoryMap { ptr: 0, entry_size: 0, entry_count: 0, desc_version: 0 };
    (*bh_ptr).acpi.rsdp = params.acpi_rsdp;
    (*bh_ptr).smbios.entry = params.smbios_entry;
    (*bh_ptr).modules.ptr = 0;
    (*bh_ptr).modules.count = 0;
    (*bh_ptr).modules.reserved = 0;
    (*bh_ptr).timing.tsc_hz = params.tsc_hz;
    (*bh_ptr).timing.unix_epoch_ms = params.unix_epoch_ms;
    init_measurements(bh_ptr, &params.crypto);
    init_rng_and_zk(bh_ptr, &params.crypto, params.rng_seed);
    (*bh_ptr).firmware = params.firmware;
    (*bh_ptr).cmdline_ptr = params.cmdline_addr;
}

unsafe fn init_measurements(bh_ptr: *mut BootHandoffV1, crypto: &CryptoHandoff) {
    (*bh_ptr).meas = Measurements {
        kernel_blake3: crypto.kernel_hash,
        kernel_sig_ok: if crypto.signature_valid { 1 } else { 0 },
        secure_boot: if crypto.secure_boot { 1 } else { 0 },
        zk_attestation_ok: if crypto.zk_attested { 1 } else { 0 },
        reserved: [0u8; 5],
    };
}

unsafe fn init_rng_and_zk(bh_ptr: *mut BootHandoffV1, crypto: &CryptoHandoff, seed: [u8; 32]) {
    (*bh_ptr).rng = RngSeed { seed32: seed };
    (*bh_ptr).zk = ZkAttestation {
        verified: if crypto.zk_attested { 1 } else { 0 },
        flags: 0,
        reserved: [0u8; 6],
        program_hash: crypto.zk_program_hash,
        capsule_commitment: crypto.zk_capsule_commitment,
    };
}
