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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FramebufferInfo {
    pub ptr: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemoryMapEntry {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemoryMap {
    pub ptr: u64,
    pub entry_size: u32,
    pub entry_count: u32,
    pub desc_version: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AcpiInfo {
    pub rsdp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SmbiosInfo {
    pub entry: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Modules {
    pub ptr: u64,
    pub count: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timing {
    pub tsc_hz: u64,
    pub unix_epoch_ms: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Measurements {
    pub kernel_sha256: [u8; 32],
    pub kernel_sig_ok: u8,
    pub secure_boot: u8,
    pub zk_attestation_ok: u8,
    pub reserved: [u8; 5],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ZkAttestation {
    pub verified: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RngSeed {
    pub seed32: [u8; 32],
}

pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;
pub const HANDOFF_VERSION: u16 = 1;

pub mod flags {
    pub const WX: u64 = 1 << 0;
    pub const NXE: u64 = 1 << 1;
    pub const SMEP: u64 = 1 << 2;
    pub const SMAP: u64 = 1 << 3;
    pub const UMIP: u64 = 1 << 4;
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
    pub const FB_AVAILABLE: u64 = 1 << 6;
    pub const ACPI_AVAILABLE: u64 = 1 << 7;
    pub const TPM_MEASURED: u64 = 1 << 8;
    pub const SECURE_BOOT: u64 = 1 << 9;
    pub const ZK_ATTESTED: u64 = 1 << 10;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootHandoffV1 {
    pub magic: u32,
    pub version: u16,
    pub size: u16,
    pub flags: u64,
    pub entry_point: u64,
    pub fb: FramebufferInfo,
    pub mmap: MemoryMap,
    pub acpi: AcpiInfo,
    pub smbios: SmbiosInfo,
    pub modules: Modules,
    pub timing: Timing,
    pub meas: Measurements,
    pub rng: RngSeed,
    pub zk: ZkAttestation,
    pub cmdline_ptr: u64,
    pub reserved0: u64,
}

impl BootHandoffV1 {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == HANDOFF_MAGIC
            && self.version == HANDOFF_VERSION
            && self.size as usize == size_of::<Self>()
    }
}

pub type KernelEntry = extern "C" fn(u64) -> !;

#[derive(Clone, Copy)]
pub struct CryptoHandoff {
    pub signature_valid: bool,
    pub secure_boot: bool,
    pub kernel_hash: [u8; 32],
    pub zk_attested: bool,
    pub zk_program_hash: [u8; 32],
    pub zk_capsule_commitment: [u8; 32],
}

impl Default for CryptoHandoff {
    fn default() -> Self {
        Self {
            signature_valid: false,
            secure_boot: false,
            kernel_hash: [0u8; 32],
            zk_attested: false,
            zk_program_hash: [0u8; 32],
            zk_capsule_commitment: [0u8; 32],
        }
    }
}
