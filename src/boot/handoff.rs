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
//
//! NØNOS Boot Handoff ABI
//!
//! Defines the shared ABI between the bootloader and kernel for passing
//! boot information. The bootloader allocates a `BootHandoffV1` structure
//! and passes its physical address in the RDI register on kernel entry.
//!
//! # Protocol
//!
//! 1. Bootloader allocates `BootHandoffV1` in boot services memory
//! 2. Bootloader fills in all available information
//! 3. Bootloader jumps to kernel entry with handoff pointer in RDI
//! 4. Kernel validates handoff using magic/version/size fields
//! 5. Kernel copies or references handoff data before reclaiming memory
//!
//! # Security
//!
//! The handoff includes security measurements and attestation data:
//! - Kernel image SHA-256 hash
//! - Signature verification status
//! - Secure boot state
//! - Random seed from hardware RNG

extern crate alloc;

use core::mem::size_of;
use spin::Once;

// ============================================================================
// Constants
// ============================================================================

/// Magic value "NONO" in little-endian (0x4E = 'N', 0x4F = 'O')
pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;

/// Current handoff protocol version
pub const HANDOFF_VERSION: u16 = 1;

/// Maximum command line length (safety limit)
const MAX_CMDLINE_LEN: usize = 4096;

// ============================================================================
// Feature Flags
// ============================================================================

/// Handoff feature flags indicating bootloader-enabled features
pub mod flags {
    /// W^X (Write XOR Execute) enforcement is active
    pub const WX: u64 = 1 << 0;
    /// NX (No-Execute) bit is enabled
    pub const NXE: u64 = 1 << 1;
    /// SMEP (Supervisor Mode Execution Prevention) is enabled
    pub const SMEP: u64 = 1 << 2;
    /// SMAP (Supervisor Mode Access Prevention) is enabled
    pub const SMAP: u64 = 1 << 3;
    /// UMIP (User-Mode Instruction Prevention) is enabled
    pub const UMIP: u64 = 1 << 4;
    /// Identity mapping preserved for low memory (<1MB)
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
    /// Framebuffer is available and valid
    pub const FB_AVAILABLE: u64 = 1 << 6;
    /// ACPI RSDP pointer is available
    pub const ACPI_AVAILABLE: u64 = 1 << 7;
    /// TPM measurements were recorded during boot
    pub const TPM_MEASURED: u64 = 1 << 8;
    /// Secure Boot is enabled in firmware
    pub const SECURE_BOOT: u64 = 1 << 9;

    /// Get human-readable flag names
    pub fn flag_names(flags: u64) -> &'static [&'static str] {
        const NAMES: [&str; 10] = [
            "W^X", "NXE", "SMEP", "SMAP", "UMIP",
            "IDMAP", "FB", "ACPI", "TPM", "SECBOOT",
        ];
        // Return appropriate subset based on flags
        &NAMES[..(64 - flags.leading_zeros() as usize).min(10)]
    }
}

// ============================================================================
// Boot Information Structures
// ============================================================================

/// Framebuffer information from bootloader
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer memory
    pub ptr: u64,
    /// Size of framebuffer in bytes
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline (pitch)
    pub stride: u32,
    /// Pixel format (0=RGB, 1=BGR, 2=RGBX, 3=BGRX)
    pub pixel_format: u32,
}

/// Pixel format constants
pub mod pixel_format {
    /// RGB (24-bit, no padding)
    pub const RGB: u32 = 0;
    /// BGR (24-bit, no padding)
    pub const BGR: u32 = 1;
    /// RGBX (32-bit, X padding)
    pub const RGBX: u32 = 2;
    /// BGRX (32-bit, X padding)
    pub const BGRX: u32 = 3;
}

impl FramebufferInfo {
    /// Check if framebuffer is valid
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.ptr != 0 && self.width > 0 && self.height > 0 && self.stride > 0
    }

    /// Get bytes per pixel
    #[inline]
    pub fn bytes_per_pixel(&self) -> u32 {
        match self.pixel_format {
            pixel_format::RGB | pixel_format::BGR => 3,
            pixel_format::RGBX | pixel_format::BGRX => 4,
            _ => 4, // Default to 32-bit
        }
    }
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

/// Main boot handoff structure passed from bootloader to kernel
///
/// The bootloader allocates this structure and passes its physical address
/// in RDI when jumping to the kernel entry point.
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
    ///
    /// # Safety
    ///
    /// The command line pointer must remain valid for the returned lifetime.
    pub unsafe fn cmdline(&self) -> Option<&'static str> {
        if self.cmdline_ptr == 0 {
            return None;
        }

        let ptr = self.cmdline_ptr as *const u8;
        let mut len = 0;

        // Find null terminator with safety limit
        while len < MAX_CMDLINE_LEN && *ptr.add(len) != 0 {
            len += 1;
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

// ============================================================================
// Global Handoff Storage
// ============================================================================

/// Global boot handoff storage (initialized once during boot)
static BOOT_HANDOFF: Once<&'static BootHandoffV1> = Once::new();

// ============================================================================
// Errors
// ============================================================================

/// Handoff initialization errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// Null pointer provided
    NullPointer,
    /// Invalid magic value
    InvalidMagic,
    /// Version mismatch
    VersionMismatch { expected: u16, got: u16 },
    /// Size mismatch
    SizeMismatch { expected: u16, got: u16 },
    /// Already initialized
    AlreadyInitialized,
}

impl HandoffError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NullPointer => "Null handoff pointer",
            Self::InvalidMagic => "Invalid handoff magic value",
            Self::VersionMismatch { .. } => "Handoff version mismatch",
            Self::SizeMismatch { .. } => "Handoff size mismatch",
            Self::AlreadyInitialized => "Handoff already initialized",
        }
    }
}

impl core::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionMismatch { expected, got } => {
                write!(f, "Handoff version mismatch: expected {}, got {}", expected, got)
            }
            Self::SizeMismatch { expected, got } => {
                write!(f, "Handoff size mismatch: expected {}, got {}", expected, got)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

// ============================================================================
// Initialization and Access
// ============================================================================

/// Initialize boot handoff from pointer
///
/// # Safety
///
/// - Must be called exactly once during early boot
/// - `ptr` must point to a valid `BootHandoffV1` structure
/// - The memory must remain valid for the kernel's lifetime
///
/// # Returns
///
/// Reference to the validated handoff structure.
pub unsafe fn init_handoff(ptr: u64) -> Result<&'static BootHandoffV1, HandoffError> {
    if ptr == 0 {
        return Err(HandoffError::NullPointer);
    }

    let handoff = &*(ptr as *const BootHandoffV1);

    // Validate magic
    if handoff.magic != HANDOFF_MAGIC {
        return Err(HandoffError::InvalidMagic);
    }

    // Validate version
    if handoff.version != HANDOFF_VERSION {
        return Err(HandoffError::VersionMismatch {
            expected: HANDOFF_VERSION,
            got: handoff.version,
        });
    }

    // Validate size
    let expected_size = size_of::<BootHandoffV1>() as u16;
    if handoff.size != expected_size {
        return Err(HandoffError::SizeMismatch {
            expected: expected_size,
            got: handoff.size,
        });
    }

    // Store in global (once)
    if BOOT_HANDOFF.get().is_some() {
        return Err(HandoffError::AlreadyInitialized);
    }

    BOOT_HANDOFF.call_once(|| handoff);
    Ok(handoff)
}

/// Get the boot handoff if initialized
#[inline]
pub fn get_handoff() -> Option<&'static BootHandoffV1> {
    BOOT_HANDOFF.get().copied()
}

/// Check if handoff has been initialized
#[inline]
pub fn is_initialized() -> bool {
    BOOT_HANDOFF.get().is_some()
}

/// Get total usable memory from handoff
pub fn total_memory() -> u64 {
    get_handoff()
        .map(|h| unsafe { h.mmap.total_usable_memory() })
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handoff_size() {
        // Ensure structure fits in a single page for ABI compatibility
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

        // No framebuffer by default
        assert!(h.framebuffer().is_none());

        // Set flag but no pointer
        h.flags = flags::FB_AVAILABLE;
        assert!(h.framebuffer().is_none());

        // Set pointer
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
    fn test_error_display() {
        let e = HandoffError::NullPointer;
        assert_eq!(e.as_str(), "Null handoff pointer");

        let e = HandoffError::VersionMismatch { expected: 1, got: 2 };
        let s = alloc::format!("{}", e);
        assert!(s.contains("1"));
        assert!(s.contains("2"));
    }

    #[test]
    fn test_magic_value() {
        // "NONO" in ASCII
        assert_eq!(HANDOFF_MAGIC, 0x4E_4F_4E_4F);
        assert_eq!((HANDOFF_MAGIC >> 24) as u8, b'O');
        assert_eq!(((HANDOFF_MAGIC >> 16) & 0xFF) as u8, b'N');
    }
}
