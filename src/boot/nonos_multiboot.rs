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
//! Multiboot2 Boot Protocol Support
//!
//! # Features
//! - Memory map parsing with UEFI-compatible region types
//! - Framebuffer information extraction
//! - Boot module loading support
//! - Platform detection (QEMU, VM, bare-metal)
//! - Platform-specific optimizations

extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use x86_64::{PhysAddr, VirtAddr};

// ============================================================================
// Errors
// ============================================================================

/// Multiboot parsing errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultibootError {
    /// Multiboot info structure is too small
    InvalidSize,
    /// Invalid tag encountered
    InvalidTag { tag_type: u32 },
    /// Memory map parsing failed
    MemoryMapError,
    /// Framebuffer info parsing failed
    FramebufferError,
    /// Module info parsing failed
    ModuleError,
    /// Invalid UTF-8 in command line
    InvalidCmdline,
}

impl MultibootError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSize => "Invalid multiboot info size",
            Self::InvalidTag { .. } => "Invalid multiboot tag",
            Self::MemoryMapError => "Memory map parsing failed",
            Self::FramebufferError => "Framebuffer info parsing failed",
            Self::ModuleError => "Module info parsing failed",
            Self::InvalidCmdline => "Invalid UTF-8 in command line",
        }
    }
}

impl core::fmt::Display for MultibootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTag { tag_type } => {
                write!(f, "Invalid multiboot tag type: {}", tag_type)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

// ============================================================================
// Multiboot Structures
// ============================================================================

/// Multiboot2 header structure (for reference)
#[repr(C, align(8))]
pub struct Multiboot2Header {
    /// Magic number (0xE85250D6)
    pub magic: u32,
    /// Architecture (0 = i386, 4 = MIPS)
    pub architecture: u32,
    /// Total header length
    pub header_length: u32,
    /// Checksum (magic + arch + len + checksum = 0)
    pub checksum: u32,
}

/// Multiboot2 boot information header
#[repr(C)]
pub struct Multiboot2Info {
    /// Total size of boot information
    pub total_size: u32,
    /// Reserved (always 0)
    pub reserved: u32,
}

/// Memory map entry from Multiboot2
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    /// Base physical address
    pub base_addr: u64,
    /// Region length in bytes
    pub length: u64,
    /// Memory type (1 = available, 2 = reserved, etc.)
    pub entry_type: u32,
    /// Reserved field
    pub reserved: u32,
}

/// Memory type constants
pub mod memory_type {
    /// Available RAM
    pub const AVAILABLE: u32 = 1;
    /// Reserved/unusable
    pub const RESERVED: u32 = 2;
    /// ACPI reclaimable
    pub const ACPI_RECLAIMABLE: u32 = 3;
    /// ACPI NVS
    pub const ACPI_NVS: u32 = 4;
    /// Bad memory
    pub const BAD_MEMORY: u32 = 5;
}

impl MemoryMapEntry {
    /// Check if region is available for use
    #[inline]
    pub fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    /// Get start physical address
    #[inline]
    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    /// Get end physical address
    #[inline]
    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    /// Get region size in bytes
    #[inline]
    pub fn size(&self) -> u64 {
        self.length
    }

    /// Get region size in pages (4KiB)
    #[inline]
    pub fn page_count(&self) -> u64 {
        self.length / 4096
    }
}

// ============================================================================
// Tag Parsing
// ============================================================================

/// Multiboot2 tag types
mod tag_type {
    pub const END: u32 = 0;
    pub const CMDLINE: u32 = 1;
    pub const BOOTLOADER_NAME: u32 = 2;
    pub const MODULE: u32 = 3;
    pub const BASIC_MEMINFO: u32 = 4;
    pub const BOOTDEV: u32 = 5;
    pub const MMAP: u32 = 6;
    pub const VBE: u32 = 7;
    pub const FRAMEBUFFER: u32 = 8;
    pub const ELF_SECTIONS: u32 = 9;
    pub const APM: u32 = 10;
}

/// Tag header common to all Multiboot2 tags
#[repr(C)]
struct TagHeader {
    tag_type: u32,
    size: u32,
}

/// Parse the multiboot2 information structure and extract all relevant boot data.
///
/// # Safety
///
/// - `info_addr` must point to a valid Multiboot2 information structure
/// - The memory must remain valid for the lifetime of returned data
///
/// # Returns
///
/// Parsed multiboot information containing memory map, framebuffer, and modules.
pub unsafe fn parse_multiboot_info(info_addr: VirtAddr) -> Result<MultibootInfo, MultibootError> {
    let info = &*info_addr.as_ptr::<Multiboot2Info>();
    if info.total_size < 8 {
        return Err(MultibootError::InvalidSize);
    }

    let mut memory_map = None;
    let mut framebuffer_info = None;
    let mut module_info = None;

    let mut tag_ptr = (info_addr + 8u64).as_ptr::<u8>();
    let end_ptr = (info_addr + info.total_size as u64).as_ptr::<u8>();

    while tag_ptr < end_ptr {
        let tag_header = &*(tag_ptr as *const TagHeader);

        // End tag terminates parsing
        if tag_header.tag_type == tag_type::END && tag_header.size == 8 {
            break;
        }

        match tag_header.tag_type {
            tag_type::MMAP => {
                memory_map = Some(parse_memory_map(tag_ptr)?);
            }
            tag_type::FRAMEBUFFER => {
                framebuffer_info = Some(parse_framebuffer_info(tag_ptr)?);
            }
            tag_type::MODULE => {
                module_info = Some(parse_module_info(tag_ptr)?);
            }
            _ => {} // Skip unknown/unused tags
        }

        // Advance to next tag (8-byte aligned)
        let next_offset = (tag_header.size + 7) & !7;
        tag_ptr = tag_ptr.add(next_offset as usize);
    }

    Ok(MultibootInfo {
        memory_map: memory_map.unwrap_or_default(),
        framebuffer_info,
        module_info,
    })
}

// ============================================================================
// Parsed Information
// ============================================================================

/// Parsed multiboot boot information
#[derive(Debug, Clone)]
pub struct MultibootInfo {
    /// Memory regions from bootloader
    pub memory_map: Vec<MemoryMapEntry>,
    /// Framebuffer information (if available)
    pub framebuffer_info: Option<FramebufferInfo>,
    /// First boot module (if loaded)
    pub module_info: Option<ModuleInfo>,
}

impl MultibootInfo {
    /// Get total available memory in bytes
    pub fn total_available_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.length)
            .sum()
    }

    /// Get available memory regions above 1MB
    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryMapEntry> {
        self.memory_map
            .iter()
            .filter(|e| e.is_available() && e.base_addr >= 0x100000)
    }

    /// Check if framebuffer is available
    #[inline]
    pub fn has_framebuffer(&self) -> bool {
        self.framebuffer_info.is_some()
    }

    /// Check if a boot module was loaded
    #[inline]
    pub fn has_module(&self) -> bool {
        self.module_info.is_some()
    }
}

/// Framebuffer information from Multiboot2
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer memory
    pub addr: PhysAddr,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline (pitch)
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u8,
    /// Framebuffer type (0=indexed, 1=RGB, 2=EGA text)
    pub framebuffer_type: u8,
}

impl FramebufferInfo {
    /// Get framebuffer size in bytes
    #[inline]
    pub fn size(&self) -> usize {
        (self.pitch as usize) * (self.height as usize)
    }

    /// Check if this is an RGB framebuffer
    #[inline]
    pub fn is_rgb(&self) -> bool {
        self.framebuffer_type == 1
    }

    /// Check if this is a text mode framebuffer
    #[inline]
    pub fn is_text_mode(&self) -> bool {
        self.framebuffer_type == 2
    }
}

/// Boot module information from Multiboot2
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Start physical address
    pub start: PhysAddr,
    /// End physical address
    pub end: PhysAddr,
    /// Optional command line string
    pub cmdline: Option<&'static str>,
}

impl ModuleInfo {
    /// Get module size in bytes
    #[inline]
    pub fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

// ============================================================================
// Internal Tag Parsing
// ============================================================================

/// Parse memory map tag
unsafe fn parse_memory_map(tag_ptr: *const u8) -> Result<Vec<MemoryMapEntry>, MultibootError> {
    #[repr(C)]
    struct MemoryMapTag {
        tag_type: u32,
        size: u32,
        entry_size: u32,
        entry_version: u32,
    }

    let tag = &*(tag_ptr as *const MemoryMapTag);

    // Validate entry size
    if tag.entry_size < 24 {
        return Err(MultibootError::MemoryMapError);
    }

    let header_size = 16u32;
    let entries_size = tag.size.saturating_sub(header_size);
    let num_entries = entries_size / tag.entry_size;
    let mut entries = Vec::with_capacity(num_entries as usize);

    let entry_ptr = tag_ptr.add(header_size as usize) as *const MemoryMapEntry;
    for i in 0..num_entries {
        entries.push(*entry_ptr.add(i as usize));
    }

    Ok(entries)
}

/// Parse framebuffer tag
unsafe fn parse_framebuffer_info(tag_ptr: *const u8) -> Result<FramebufferInfo, MultibootError> {
    #[repr(C)]
    struct FramebufferTag {
        tag_type: u32,
        size: u32,
        framebuffer_addr: u64,
        framebuffer_pitch: u32,
        framebuffer_width: u32,
        framebuffer_height: u32,
        framebuffer_bpp: u8,
        framebuffer_type: u8,
        reserved: u8,
    }

    let tag = &*(tag_ptr as *const FramebufferTag);

    Ok(FramebufferInfo {
        addr: PhysAddr::new(tag.framebuffer_addr),
        width: tag.framebuffer_width,
        height: tag.framebuffer_height,
        pitch: tag.framebuffer_pitch,
        bpp: tag.framebuffer_bpp,
        framebuffer_type: tag.framebuffer_type,
    })
}

/// Parse module tag
unsafe fn parse_module_info(tag_ptr: *const u8) -> Result<ModuleInfo, MultibootError> {
    #[repr(C)]
    struct ModuleTag {
        tag_type: u32,
        size: u32,
        mod_start: u32,
        mod_end: u32,
    }

    let tag = &*(tag_ptr as *const ModuleTag);

    // Parse command line if present (after the fixed header)
    let header_size = 16usize;
    let cmdline = if tag.size as usize > header_size {
        let cmdline_ptr = tag_ptr.add(header_size);
        let max_len = (tag.size as usize).saturating_sub(header_size);

        // Find null terminator
        let mut len = 0;
        while len < max_len && *cmdline_ptr.add(len) != 0 {
            len += 1;
        }

        if len > 0 {
            let bytes = slice::from_raw_parts(cmdline_ptr, len);
            core::str::from_utf8(bytes).ok()
        } else {
            None
        }
    } else {
        None
    };

    Ok(ModuleInfo {
        start: PhysAddr::new(tag.mod_start as u64),
        end: PhysAddr::new(tag.mod_end as u64),
        cmdline,
    })
}

// ============================================================================
// Platform Detection
// ============================================================================

/// Detected platform type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// QEMU emulator with TCG or KVM
    Qemu,
    /// Other hypervisor/virtual machine
    VirtualMachine,
    /// Physical hardware
    BareMetal,
}

impl Platform {
    /// Get platform description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Qemu => "QEMU",
            Self::VirtualMachine => "Virtual Machine",
            Self::BareMetal => "Bare Metal",
        }
    }

    /// Check if running in a virtualized environment
    #[inline]
    pub fn is_virtual(&self) -> bool {
        !matches!(self, Self::BareMetal)
    }

    /// Apply platform-specific optimizations
    pub fn optimize_for_platform(&self) {
        match self {
            Self::Qemu => {
                crate::log::info!("Detected QEMU - applying virtualization optimizations");
            }
            Self::VirtualMachine => {
                crate::log::info!("Detected virtual machine - applying general VM optimizations");
            }
            Self::BareMetal => {
                crate::log::info!("Detected bare-metal hardware - applying hardware optimizations");
            }
        }
    }

    /// Get recommended timer frequency in Hz
    #[inline]
    pub fn timer_frequency(&self) -> u32 {
        match self {
            Self::Qemu => 1000,
            Self::VirtualMachine => 100,
            Self::BareMetal => 1000,
        }
    }

    /// Check if VirtIO devices are likely available
    #[inline]
    pub fn supports_virtio(&self) -> bool {
        matches!(self, Self::Qemu | Self::VirtualMachine)
    }

    /// Get recommended console type
    #[inline]
    pub fn console_type(&self) -> ConsoleType {
        match self {
            Self::Qemu => ConsoleType::Serial,
            Self::VirtualMachine | Self::BareMetal => ConsoleType::Vga,
        }
    }
}

impl core::fmt::Display for Platform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Console output type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    /// VGA text mode
    Vga,
    /// Serial port (COM1)
    Serial,
    /// Graphics framebuffer
    Framebuffer,
}

impl ConsoleType {
    /// Get console type description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Vga => "VGA",
            Self::Serial => "Serial",
            Self::Framebuffer => "Framebuffer",
        }
    }
}

impl core::fmt::Display for ConsoleType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detect if running on QEMU, other VM, or bare-metal
///
/// Uses CPUID hypervisor leaf (0x40000000) to detect virtualization
/// and identify specific hypervisors by their signature.
pub fn detect_platform() -> Platform {
    // QEMU/TCG hypervisor signature: "TCGTCGTCGTCG"
    const QEMU_SIG_EBX: u32 = 0x5447_4354; // "TCGT" (little-endian)
    const QEMU_SIG_ECX: u32 = 0x5447_4354;
    const QEMU_SIG_EDX: u32 = 0x5447_4354;

    unsafe {
        let cpuid_result = core::arch::x86_64::__cpuid(0x4000_0000);

        // Check for QEMU/TCG signature
        if cpuid_result.ebx == QEMU_SIG_EBX
            && cpuid_result.ecx == QEMU_SIG_ECX
            && cpuid_result.edx == QEMU_SIG_EDX
        {
            return Platform::Qemu;
        }

        // Any hypervisor present if max leaf >= 0x40000000
        if cpuid_result.eax >= 0x4000_0000 {
            return Platform::VirtualMachine;
        }

        Platform::BareMetal
    }
}

// ============================================================================
// Memory Region Helpers
// ============================================================================

/// Get safe memory regions from multiboot info or platform defaults
///
/// Filters memory map for usable regions above 1MB and at least one page.
/// Falls back to conservative defaults if no memory map is available.
pub fn get_safe_memory_regions(
    platform: Platform,
    multiboot_info: &MultibootInfo,
) -> Vec<crate::memory::layout::Region> {
    let mut regions = Vec::new();

    // Extract usable regions from memory map
    for entry in &multiboot_info.memory_map {
        // Only use available memory above 1MB with at least one page
        if entry.is_available() && entry.length >= 4096 && entry.base_addr >= 0x10_0000 {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    // Fallback to conservative defaults if no memory map available
    if regions.is_empty() {
        let (start, end) = match platform {
            Platform::Qemu => (0x10_0000, 0x800_0000),       // 1MB - 128MB
            Platform::VirtualMachine => (0x10_0000, 0x400_0000), // 1MB - 64MB
            Platform::BareMetal => (0x10_0000, 0x200_0000),     // 1MB - 32MB
        };

        regions.push(crate::memory::layout::Region {
            start,
            end,
            kind: crate::memory::layout::RegionKind::Usable,
        });
    }

    regions
}

// ============================================================================
// Platform Initialization
// ============================================================================

/// Initialize platform-specific features
///
/// Detects platform and applies appropriate optimizations.
pub fn init_platform_features(platform: Platform) -> Result<(), MultibootError> {
    platform.optimize_for_platform();

    match platform {
        Platform::Qemu => init_qemu_features(),
        Platform::VirtualMachine => init_vm_features(),
        Platform::BareMetal => init_baremetal_features(),
    }

    Ok(())
}

/// QEMU-specific initialization
fn init_qemu_features() {
    crate::log::info!("Initialized QEMU-specific features");
    // Enable paravirt optimizations, debug ports, etc.
}

/// Generic VM initialization
fn init_vm_features() {
    crate::log::info!("Initialized general VM features");
    // Enable hypercalls, reduce timer polling, etc.
}

/// Bare-metal hardware initialization
fn init_baremetal_features() {
    crate::log::info!("Initialized bare-metal hardware features");
    // Enable full hardware access, power management, etc.
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_memory_entry_helpers() {
        let entry = MemoryMapEntry {
            base_addr: 0x10_0000,
            length: 0x100_0000, // 16MB
            entry_type: memory_type::AVAILABLE,
            reserved: 0,
        };

        assert!(entry.is_available());
        assert_eq!(entry.start_addr().as_u64(), 0x10_0000);
        assert_eq!(entry.end_addr().as_u64(), 0x110_0000);
        assert_eq!(entry.size(), 0x100_0000);
        assert_eq!(entry.page_count(), 4096); // 16MB / 4KB
    }

    #[test]
    fn test_memory_entry_reserved() {
        let entry = MemoryMapEntry {
            base_addr: 0,
            length: 0x10_0000,
            entry_type: memory_type::RESERVED,
            reserved: 0,
        };

        assert!(!entry.is_available());
    }

    #[test]
    fn test_multiboot_info_helpers() {
        let info = MultibootInfo {
            memory_map: vec![
                MemoryMapEntry {
                    base_addr: 0,
                    length: 0x10_0000,
                    entry_type: memory_type::RESERVED,
                    reserved: 0,
                },
                MemoryMapEntry {
                    base_addr: 0x10_0000,
                    length: 0x100_0000,
                    entry_type: memory_type::AVAILABLE,
                    reserved: 0,
                },
            ],
            framebuffer_info: None,
            module_info: None,
        };

        assert_eq!(info.total_available_memory(), 0x100_0000);
        assert_eq!(info.usable_regions().count(), 1);
        assert!(!info.has_framebuffer());
        assert!(!info.has_module());
    }

    #[test]
    fn test_framebuffer_helpers() {
        let fb = FramebufferInfo {
            addr: PhysAddr::new(0xFD00_0000),
            width: 800,
            height: 600,
            pitch: 3200,
            bpp: 32,
            framebuffer_type: 1, // RGB
        };

        assert_eq!(fb.size(), 3200 * 600);
        assert!(fb.is_rgb());
        assert!(!fb.is_text_mode());
    }

    #[test]
    fn test_module_size() {
        let module = ModuleInfo {
            start: PhysAddr::new(0x20_0000),
            end: PhysAddr::new(0x30_0000),
            cmdline: Some("init=/bin/init"),
        };

        assert_eq!(module.size(), 0x10_0000); // 1MB
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Qemu.as_str(), "QEMU");
        assert_eq!(Platform::VirtualMachine.as_str(), "Virtual Machine");
        assert_eq!(Platform::BareMetal.as_str(), "Bare Metal");
    }

    #[test]
    fn test_platform_is_virtual() {
        assert!(Platform::Qemu.is_virtual());
        assert!(Platform::VirtualMachine.is_virtual());
        assert!(!Platform::BareMetal.is_virtual());
    }

    #[test]
    fn test_platform_virtio_support() {
        assert!(Platform::Qemu.supports_virtio());
        assert!(Platform::VirtualMachine.supports_virtio());
        assert!(!Platform::BareMetal.supports_virtio());
    }

    #[test]
    fn test_console_type_display() {
        assert_eq!(ConsoleType::Serial.as_str(), "Serial");
        assert_eq!(ConsoleType::Vga.as_str(), "VGA");
        assert_eq!(ConsoleType::Framebuffer.as_str(), "Framebuffer");
    }

    #[test]
    fn test_error_display() {
        let e = MultibootError::InvalidSize;
        assert_eq!(e.as_str(), "Invalid multiboot info size");

        let e = MultibootError::InvalidTag { tag_type: 99 };
        let s = alloc::format!("{}", e);
        assert!(s.contains("99"));
    }

    #[test]
    fn test_get_safe_memory_fallback() {
        let empty_info = MultibootInfo {
            memory_map: vec![],
            framebuffer_info: None,
            module_info: None,
        };

        // Should return fallback regions
        let regions = get_safe_memory_regions(Platform::Qemu, &empty_info);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].start, 0x10_0000);
        assert_eq!(regions[0].end, 0x800_0000);
    }
}
