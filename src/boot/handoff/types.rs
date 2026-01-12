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

pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;
pub const HANDOFF_VERSION: u16 = 1;
pub(crate) const MAX_CMDLINE_LEN: usize = 4096;

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

    pub fn flag_names(flags: u64) -> &'static [&'static str] {
        const NAMES: [&str; 10] = [
            "W^X", "NXE", "SMEP", "SMAP", "UMIP", "IDMAP", "FB", "ACPI", "TPM", "SECBOOT",
        ];
        &NAMES[..(64 - flags.leading_zeros() as usize).min(10)]
    }
}

pub mod pixel_format {
    pub const RGB: u32 = 0;
    pub const BGR: u32 = 1;
    pub const RGBX: u32 = 2;
    pub const BGRX: u32 = 3;
}

pub mod memory_type {
    pub const RESERVED: u32 = 0;
    pub const LOADER_CODE: u32 = 1;
    pub const LOADER_DATA: u32 = 2;
    pub const BOOT_SERVICES_CODE: u32 = 3;
    pub const BOOT_SERVICES_DATA: u32 = 4;
    pub const RUNTIME_SERVICES_CODE: u32 = 5;
    pub const RUNTIME_SERVICES_DATA: u32 = 6;
    pub const CONVENTIONAL: u32 = 7;
    pub const UNUSABLE: u32 = 8;
    pub const ACPI_RECLAIM: u32 = 9;
    pub const ACPI_NVS: u32 = 10;
    pub const MMIO: u32 = 11;
    pub const MMIO_PORT_SPACE: u32 = 12;
    pub const PAL_CODE: u32 = 13;
    pub const PERSISTENT: u32 = 14;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FramebufferInfo {
    pub ptr: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
}

impl FramebufferInfo {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.ptr != 0 && self.width > 0 && self.height > 0 && self.stride > 0
    }

    #[inline]
    pub fn bytes_per_pixel(&self) -> u32 {
        match self.pixel_format {
            pixel_format::RGB | pixel_format::BGR => 3,
            pixel_format::RGBX | pixel_format::BGRX => 4,
            _ => 4,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryMap {
    pub ptr: u64,
    pub entry_size: u32,
    pub entry_count: u32,
    pub desc_version: u32,
}

impl MemoryMap {
    // # SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn entries(&self) -> &[MemoryMapEntry] { unsafe {
        if self.ptr == 0 || self.entry_count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr as *const MemoryMapEntry, self.entry_count as usize)
    }}

    // # SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn usable_regions(&self) -> impl Iterator<Item = (u64, u64)> + '_ { unsafe {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| (e.physical_start, e.physical_start + e.page_count * 4096))
    }}

    // # SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn total_usable_memory(&self) -> u64 { unsafe {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| e.page_count * 4096)
            .sum()
    }}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiInfo {
    pub rsdp: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmbiosInfo {
    pub entry: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub kind: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    pub ptr: u64,
    pub count: u32,
    pub reserved: u32,
}

impl Modules {
    // # SAFETY: Caller must ensure ptr points to valid Module array
    pub unsafe fn modules(&self) -> &[Module] { unsafe {
        if self.ptr == 0 || self.count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr as *const Module, self.count as usize)
    }}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    pub tsc_hz: u64,
    pub unix_epoch_ms: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    pub kernel_sha256: [u8; 32],
    pub kernel_sig_ok: u8,
    pub secure_boot: u8,
    pub reserved: [u8; 6],
}

impl Default for Measurements {
    fn default() -> Self {
        Self {
            kernel_sha256: [0; 32],
            kernel_sig_ok: 0,
            secure_boot: 0,
            reserved: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RngSeed {
    pub seed32: [u8; 32],
}

impl Default for RngSeed {
    fn default() -> Self {
        Self { seed32: [0; 32] }
    }
}

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
    /// # Safety {
    /// the command line pointer must remain valid for the returned lifetime.
    /// the pointer must point to valid UTF-8 data.
    /// }
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
        // # SAFETY: Caller guarantees cmdline_ptr is valid
        while len < MAX_CMDLINE_LEN {
            let byte = unsafe { *ptr.add(len) };
            if byte == 0 {
                break;
            }
            // Reject non-printable characters (except common whitespace)
            if byte < 0x20 && byte != b'\t' && byte != b'\n' && byte != b'\r' {
                return None;
            }
            len += 1;
        }

        if len == 0 {
            return None;
        }

        // # SAFETY: len validated above
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
            cmdline_ptr: 0,
            reserved0: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    #[test]
    fn test_handoff_size() {
        assert!(size_of::<BootHandoffV1>() < 4096);
    }

    #[test]
    fn test_default_valid() {
        let h = BootHandoffV1::default();
        assert!(h.is_valid());
        assert_eq!(h.magic, HANDOFF_MAGIC);
        assert_eq!(h.version, HANDOFF_VERSION);
    }

    #[test]
    fn test_flags() {
        let mut h = BootHandoffV1::default();
        h.flags = flags::WX | flags::NXE | flags::SMEP;

        assert!(h.has_flag(flags::WX));
        assert!(h.has_flag(flags::NXE));
        assert!(h.has_flag(flags::SMEP));
        assert!(!h.has_flag(flags::SMAP));
        assert!(!h.has_flag(flags::FB_AVAILABLE));
    }

    #[test]
    fn test_framebuffer_available() {
        let mut h = BootHandoffV1::default();

        assert!(h.framebuffer().is_none());

        h.flags = flags::FB_AVAILABLE;
        assert!(h.framebuffer().is_none());

        h.fb.ptr = 0xFD00_0000;
        assert!(h.framebuffer().is_some());
    }

    #[test]
    fn test_acpi_available() {
        let mut h = BootHandoffV1::default();

        assert!(h.acpi_rsdp().is_none());

        h.flags = flags::ACPI_AVAILABLE;
        h.acpi.rsdp = 0xE0000;
        assert_eq!(h.acpi_rsdp(), Some(0xE0000));
    }

    #[test]
    fn test_secure_boot() {
        let mut h = BootHandoffV1::default();

        assert!(!h.secure_boot_enabled());

        h.flags = flags::SECURE_BOOT;
        assert!(h.secure_boot_enabled());

        h.flags = 0;
        h.meas.secure_boot = 1;
        assert!(h.secure_boot_enabled());
    }

    #[test]
    fn test_kernel_verified() {
        let mut h = BootHandoffV1::default();

        assert!(!h.kernel_verified());

        h.meas.kernel_sig_ok = 1;
        assert!(h.kernel_verified());
    }

    #[test]
    fn test_memory_map_empty() {
        let mmap = MemoryMap::default();
        unsafe {
            assert!(mmap.entries().is_empty());
            assert_eq!(mmap.total_usable_memory(), 0);
        }
    }

    #[test]
    fn test_modules_empty() {
        let modules = Modules::default();
        unsafe {
            assert!(modules.modules().is_empty());
        }
    }

    #[test]
    fn test_framebuffer_info_valid() {
        let mut fb = FramebufferInfo::default();
        assert!(!fb.is_valid());
        fb.ptr = 0xFD00_0000;
        fb.width = 800;
        fb.height = 600;
        fb.stride = 3200;
        assert!(fb.is_valid());
    }

    #[test]
    fn test_framebuffer_bytes_per_pixel() {
        let mut fb = FramebufferInfo::default();

        fb.pixel_format = pixel_format::RGB;
        assert_eq!(fb.bytes_per_pixel(), 3);

        fb.pixel_format = pixel_format::BGR;
        assert_eq!(fb.bytes_per_pixel(), 3);

        fb.pixel_format = pixel_format::RGBX;
        assert_eq!(fb.bytes_per_pixel(), 4);

        fb.pixel_format = pixel_format::BGRX;
        assert_eq!(fb.bytes_per_pixel(), 4);
    }

    #[test]
    fn test_magic_value() {
        assert_eq!(HANDOFF_MAGIC, 0x4E_4F_4E_4F);
        assert_eq!((HANDOFF_MAGIC >> 24) as u8, b'O');
        assert_eq!(((HANDOFF_MAGIC >> 16) & 0xFF) as u8, b'N');
    }
}
