// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::constants::{flags, HANDOFF_MAGIC, HANDOFF_VERSION, MAX_CMDLINE_LEN};
use super::framebuffer::FramebufferInfo;
use super::memory::MemoryMap;
use super::info::{AcpiInfo, SmbiosInfo, Modules, Timing};
use super::security::{Measurements, ZkAttestation, RngSeed};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

    #[inline]
    pub fn has_flag(&self, flag: u64) -> bool {
        self.flags & flag != 0
    }

    pub fn framebuffer(&self) -> Option<&FramebufferInfo> {
        if self.has_flag(flags::FB_AVAILABLE) && self.fb.ptr != 0 {
            Some(&self.fb)
        } else {
            None
        }
    }

    pub fn acpi_rsdp(&self) -> Option<u64> {
        if self.has_flag(flags::ACPI_AVAILABLE) && self.acpi.rsdp != 0 {
            Some(self.acpi.rsdp)
        } else {
            None
        }
    }

    // SAFETY: The command line pointer must remain valid for the returned lifetime.
    pub unsafe fn cmdline(&self) -> Option<&'static str> {
        const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

        if self.cmdline_ptr == 0 {
            return None;
        }

        if self.cmdline_ptr > MAX_PHYS_ADDR {
            return None;
        }

        let ptr = self.cmdline_ptr as *const u8;
        let mut len = 0;

        // SAFETY: Caller guarantees cmdline_ptr is valid
        while len < MAX_CMDLINE_LEN {
            let byte = unsafe { *ptr.add(len) };
            if byte == 0 {
                break;
            }
            if byte < 0x20 && byte != b'\t' && byte != b'\n' && byte != b'\r' {
                return None;
            }
            len += 1;
        }

        if len == 0 {
            return None;
        }

        // SAFETY: len validated above
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        core::str::from_utf8(slice).ok()
    }

    pub fn secure_boot_enabled(&self) -> bool {
        self.has_flag(flags::SECURE_BOOT) || self.meas.secure_boot != 0
    }

    pub fn kernel_verified(&self) -> bool {
        self.meas.kernel_sig_ok != 0
    }
}

impl Default for BootHandoffV1 {
    fn default() -> Self {
        Self {
            magic: HANDOFF_MAGIC,
            version: HANDOFF_VERSION,
            size: size_of::<Self>() as u16,
            flags: 0,
            entry_point: 0,
            fb: FramebufferInfo::default(),
            mmap: MemoryMap::default(),
            acpi: AcpiInfo::default(),
            smbios: SmbiosInfo::default(),
            modules: Modules::default(),
            timing: Timing::default(),
            meas: Measurements::default(),
            rng: RngSeed::default(),
            zk: ZkAttestation::default(),
            cmdline_ptr: 0,
            reserved0: 0,
        }
    }
}
