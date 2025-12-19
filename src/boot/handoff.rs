// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

//! NONOS Boot Handoff ABI

#![allow(dead_code)]

use core::mem::size_of;

/// Magic value "NONO" in little-endian
pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;

/// Current handoff version
pub const HANDOFF_VERSION: u16 = 1;

/// Handoff feature flags
pub mod flags {
    /// W^X enforcement is active
    pub const WX: u64 = 1 << 0;
    /// NX bit is enabled
    pub const NXE: u64 = 1 << 1;
    /// SMEP is enabled
    pub const SMEP: u64 = 1 << 2;
    /// SMAP is enabled
    pub const SMAP: u64 = 1 << 3;
    /// UMIP is enabled
    pub const UMIP: u64 = 1 << 4;
    /// Identity mapping preserved for low memory
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
    /// Framebuffer is available
    pub const FB_AVAILABLE: u64 = 1 << 6;
    /// ACPI RSDP is available
    pub const ACPI_AVAILABLE: u64 = 1 << 7;
    /// TPM measurements available
    pub const TPM_MEASURED: u64 = 1 << 8;
    /// Secure boot is enabled
    pub const SECURE_BOOT: u64 = 1 << 9;
}

/// Framebuffer information from bootloader
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub ptr: u64,
    /// Size of framebuffer in bytes
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline
    pub stride: u32,
    /// Pixel format (0=RGB, 1=BGR, 2=RGBX, 3=BGRX)
    pub pixel_format: u32,
}

/// Memory map entry compatible with UEFI memory descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    /// Memory type
    pub memory_type: u32,
    /// Physical start address
    pub physical_start: u64,
    /// Virtual start address (if mapped)
    pub virtual_start: u64,
    /// Number of 4KiB pages
    pub page_count: u64,
    /// Attribute flags
    pub attribute: u64,
}

/// Memory type constants (UEFI compatible)
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

/// Memory map header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryMap {
    /// Pointer to array of MemoryMapEntry
    pub ptr: u64,
    /// Size of each entry
    pub entry_size: u32,
    /// Number of entries
    pub entry_count: u32,
    /// Descriptor version
    pub desc_version: u32,
}

impl MemoryMap {
    /// Get the memory map entries as a slice
    pub unsafe fn entries(&self) -> &[MemoryMapEntry] {
        if self.ptr == 0 || self.entry_count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(
            self.ptr as *const MemoryMapEntry,
            self.entry_count as usize,
        )
    }

    /// Iterate over usable memory regions
    pub unsafe fn usable_regions(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| (e.physical_start, e.physical_start + e.page_count * 4096))
    }

    /// Calculate total usable memory
    pub unsafe fn total_usable_memory(&self) -> u64 {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| e.page_count * 4096)
            .sum()
    }
}

/// ACPI information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiInfo {
    /// Physical address of RSDP
    pub rsdp: u64,
}

/// SMBIOS information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmbiosInfo {
    /// Physical address of SMBIOS entry point
    pub entry: u64,
}

/// Loaded module information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Module {
    /// Base physical address
    pub base: u64,
    /// Size in bytes
    pub size: u64,
    /// Module kind (0=initrd, 1=driver, 2=config)
    pub kind: u32,
    /// Reserved for alignment
    pub reserved: u32,
}

/// Module list header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    /// Pointer to array of Module
    pub ptr: u64,
    /// Number of modules
    pub count: u32,
    /// Reserved for alignment
    pub reserved: u32,
}

impl Modules {
    /// Get modules as a slice
    pub unsafe fn modules(&self) -> &[Module] {
        if self.ptr == 0 || self.count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr as *const Module, self.count as usize)
    }
}

/// Timing information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    /// TSC frequency in Hz (0 if unknown)
    pub tsc_hz: u64,
    /// Unix epoch in milliseconds at boot
    pub unix_epoch_ms: u64,
}

/// Security measurements from bootloader
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    /// SHA-256 hash of kernel image
    pub kernel_sha256: [u8; 32],
    /// Whether kernel signature was verified (1=yes, 0=no)
    pub kernel_sig_ok: u8,
    /// Whether secure boot is enabled (1=yes, 0=no)
    pub secure_boot: u8,
    /// Reserved for alignment
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

/// Random seed from bootloader
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RngSeed {
    /// 32 bytes of entropy
    pub seed32: [u8; 32],
}

impl Default for RngSeed {
    fn default() -> Self {
        Self { seed32: [0; 32] }
    }
}

/// The bootloader allocates this structure and passes its physical address in RDI when jumping to the kernel entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootHandoffV1 {
    /// Magic value (HANDOFF_MAGIC)
    pub magic: u32,
    /// Version (HANDOFF_VERSION)
    pub version: u16,
    /// Size of this structure
    pub size: u16,
    /// Feature flags
    pub flags: u64,
    /// Kernel entry point address
    pub entry_point: u64,
    /// Framebuffer information
    pub fb: FramebufferInfo,
    /// Memory map
    pub mmap: MemoryMap,
    /// ACPI information
    pub acpi: AcpiInfo,
    /// SMBIOS information
    pub smbios: SmbiosInfo,
    /// Loaded modules
    pub modules: Modules,
    /// Timing information
    pub timing: Timing,
    /// Security measurements
    pub meas: Measurements,
    /// Random seed
    pub rng: RngSeed,
    /// Command line pointer (null-terminated string)
    pub cmdline_ptr: u64,
    /// Reserved field (used for extended boot info page address)
    pub reserved0: u64,
}

impl BootHandoffV1 {
    /// Validate the handoff structure
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == HANDOFF_MAGIC
            && self.version == HANDOFF_VERSION
            && self.size as usize == size_of::<Self>()
    }

    /// Check if a specific flag is set
    #[inline]
    pub fn has_flag(&self, flag: u64) -> bool {
        self.flags & flag != 0
    }

    /// Get framebuffer if available
    pub fn framebuffer(&self) -> Option<&FramebufferInfo> {
        if self.has_flag(flags::FB_AVAILABLE) && self.fb.ptr != 0 {
            Some(&self.fb)
        } else {
            None
        }
    }

    /// Get ACPI RSDP if available
    pub fn acpi_rsdp(&self) -> Option<u64> {
        if self.has_flag(flags::ACPI_AVAILABLE) && self.acpi.rsdp != 0 {
            Some(self.acpi.rsdp)
        } else {
            None
        }
    }

    /// Get command line if available
    pub unsafe fn cmdline(&self) -> Option<&'static str> {
        if self.cmdline_ptr == 0 {
            return None;
        }
        let ptr = self.cmdline_ptr as *const u8;
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
            if len > 4096 {
                // Safety limit
                break;
            }
        }
        if len == 0 {
            return None;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        core::str::from_utf8(slice).ok()
    }

    /// Check if secure boot is enabled
    pub fn secure_boot_enabled(&self) -> bool {
        self.has_flag(flags::SECURE_BOOT) || self.meas.secure_boot != 0
    }

    /// Check if kernel signature was verified
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

/// Global boot handoff storage
static mut BOOT_HANDOFF: Option<&'static BootHandoffV1> = None;

/// # Safety # Initialize boot handoff from pointer.
/// Must be called exactly once during early boot with a valid pointer.
pub unsafe fn init_handoff(ptr: u64) -> Result<&'static BootHandoffV1, &'static str> {
    if ptr == 0 {
        return Err("Null handoff pointer");
    }

    let handoff = &*(ptr as *const BootHandoffV1);

    if !handoff.is_valid() {
        return Err("Invalid handoff structure");
    }

    BOOT_HANDOFF = Some(handoff);
    Ok(handoff)
}

/// Get the boot handoff if initialized
pub fn get_handoff() -> Option<&'static BootHandoffV1> {
    unsafe { BOOT_HANDOFF }
}

/// Get total usable memory from handoff
pub fn total_memory() -> u64 {
    get_handoff()
        .map(|h| unsafe { h.mmap.total_usable_memory() })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handoff_size() {
        // Ensure structure is correctly sized for ABI
        assert!(size_of::<BootHandoffV1>() < 4096);
    }

    #[test]
    fn test_default_valid() {
        let h = BootHandoffV1::default();
        assert!(h.is_valid());
    }
}
