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
use super::constants::{HANDOFF_MAGIC, HANDOFF_VERSION};
use super::framebuffer::FramebufferInfo;
use super::memory::MemoryMap;
use super::security::{Measurements, RngSeed, ZkAttestation};
use super::system::{AcpiInfo, Modules, SmbiosInfo, Timing};
use crate::firmware::FirmwareHandoff;

/// Boot handoff structure passed to kernel. Layout is ABI-stable for kernel compatibility.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootHandoffV1 { pub magic: u32, pub version: u16, pub size: u16, pub flags: u64, pub entry_point: u64, pub fb: FramebufferInfo, pub mmap: MemoryMap, pub acpi: AcpiInfo, pub smbios: SmbiosInfo, pub modules: Modules, pub timing: Timing, pub meas: Measurements, pub rng: RngSeed, pub zk: ZkAttestation, pub firmware: FirmwareHandoff, pub cmdline_ptr: u64 }

impl BootHandoffV1 {
    /// Validate handoff struct integrity: magic, version, size, and memory map consistency.
    pub fn is_valid(&self) -> bool {
        if self.magic != HANDOFF_MAGIC { return false; }
        if self.version != HANDOFF_VERSION { return false; }
        if self.size as usize != size_of::<Self>() { return false; }
        if self.entry_point == 0 { return false; }
        if self.mmap.entry_count > 0 && self.mmap.ptr == 0 { return false; }
        if self.mmap.entry_count > 0 && self.mmap.entry_size == 0 { return false; }
        true
    }
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(BootHandoffV1, magic) == 0);
    assert!(offset_of!(BootHandoffV1, version) == 4);
    assert!(offset_of!(BootHandoffV1, size) == 6);
    assert!(offset_of!(BootHandoffV1, flags) == 8);
    assert!(offset_of!(BootHandoffV1, entry_point) == 16);
    assert!(offset_of!(BootHandoffV1, fb) == 24);
    assert!(offset_of!(BootHandoffV1, mmap) == 64);
    assert!(offset_of!(BootHandoffV1, acpi) == 88);
    assert!(offset_of!(BootHandoffV1, smbios) == 96);
    assert!(offset_of!(BootHandoffV1, modules) == 104);
    assert!(offset_of!(BootHandoffV1, timing) == 120);
    assert!(offset_of!(BootHandoffV1, meas) == 136);
    assert!(offset_of!(BootHandoffV1, rng) == 176);
    assert!(offset_of!(BootHandoffV1, zk) == 208);
    assert!(offset_of!(BootHandoffV1, firmware) == 280);
    assert!(offset_of!(BootHandoffV1, cmdline_ptr) == 1824);
    assert!(size_of::<BootHandoffV1>() == 1832);
};
