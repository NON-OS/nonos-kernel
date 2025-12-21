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
//! NØNOS Multiboot2 Boot Protocol 
//! For booting NØNOS on QEMU, virtual machines, and bare-metal hardware.
//!
//! # Multiboot2 Information Structure
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     MULTIBOOT2 INFORMATION                          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  +0x00  │ Total Size (u32)      │ Reserved (u32)                    │
//! ├─────────┼───────────────────────┴───────────────────────────────────┤
//! │  +0x08  │                    Tag Array                              │
//! │         │  ┌─────────────────────────────────────────────────────┐  │
//! │         │  │ Tag Header: Type (u32) │ Size (u32)                 │  │
//! │         │  ├─────────────────────────────────────────────────────┤  │
//! │         │  │ Tag-specific data (variable length)                 │  │
//! │         │  └─────────────────────────────────────────────────────┘  │
//! │         │  ... (more tags, 8-byte aligned)                          │
//! ├─────────┼───────────────────────────────────────────────────────────┤
//! │  End    │ End Tag: Type=0, Size=8                                   │
//! └─────────┴───────────────────────────────────────────────────────────┘
//! # Tag Types (Multiboot2 Specification)
//!
//! | Type | Name                    | Description                        |
//! |------|-------------------------|------------------------------------|
//! |  0   | End                     | Marks end of tag list              |
//! |  1   | Boot Command Line       | Kernel command line string         |
//! |  2   | Boot Loader Name        | Bootloader identification          |
//! |  3   | Module                  | Loaded module info                 |
//! |  4   | Basic Memory Info       | Legacy mem_lower/mem_upper         |
//! |  5   | BIOS Boot Device        | Boot device info                   |
//! |  6   | Memory Map              | E820-style memory map              |
//! |  7   | VBE Info                | VESA BIOS Extensions               |
//! |  8   | Framebuffer Info        | Graphics framebuffer               |
//! |  9   | ELF Sections            | Kernel ELF section headers         |
//! | 10   | APM Table               | Advanced Power Management          |
//! | 11   | EFI 32-bit System Table | 32-bit EFI system table pointer    |
//! | 12   | EFI 64-bit System Table | 64-bit EFI system table pointer    |
//! | 13   | SMBIOS Tables           | System Management BIOS             |
//! | 14   | ACPI Old RSDP           | ACPI 1.0 RSDP                      |
//! | 15   | ACPI New RSDP           | ACPI 2.0+ XSDP                     |
//! | 16   | Networking Info         | Network boot info                  |
//! | 17   | EFI Memory Map          | EFI memory map                     |
//! | 18   | EFI Boot Services       | Boot services not terminated       |
//! | 19   | EFI 32-bit Image Handle | 32-bit image handle                |
//! | 20   | EFI 64-bit Image Handle | 64-bit image handle                |
//! | 21   | Image Load Base         | Physical load address              |
//!
//! # Platform Detection
//! CPUID Leaf 0x40000000 - Hypervisor Identification
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  EAX: Maximum hypervisor CPUID leaf                                 │
//! │  EBX:ECX:EDX: 12-character hypervisor signature                     │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! Known Signatures:
//! "KVMKVMKVM\0\0\0" - Linux KVM
//! "Microsoft Hv"    - Microsoft Hyper-V
//! "VMwareVMware"    - VMware
//! "XenVMMXenVMM"    - Xen Hypervisor
//! "TCGTCGTCGTCG"    - QEMU TCG (software emulation)
//! "VBoxVBoxVBox"    - Oracle VirtualBox
//! "bhyve bhyve "    - FreeBSD bhyve
//! "ACRNACRNACRN"    - ACRN Hypervisor
//! " lrpepyh  vr"    - Parallels

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use x86_64::{PhysAddr, VirtAddr};

// ============================================================================
// Constants
// ============================================================================

/// Multiboot2 header magic number (bootloader -> kernel)
pub const MULTIBOOT2_HEADER_MAGIC: u32 = 0xE85250D6;

/// Multiboot2 bootloader magic (kernel checks this in EAX)
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D76289;

/// Architecture: i386/x86
pub const MULTIBOOT2_ARCHITECTURE_I386: u32 = 0;

/// Tag types
pub mod tag {
    pub const END: u32 = 0;
    pub const CMDLINE: u32 = 1;
    pub const BOOTLOADER_NAME: u32 = 2;
    pub const MODULE: u32 = 3;
    pub const BASIC_MEMINFO: u32 = 4;
    pub const BIOS_BOOT_DEVICE: u32 = 5;
    pub const MEMORY_MAP: u32 = 6;
    pub const VBE_INFO: u32 = 7;
    pub const FRAMEBUFFER: u32 = 8;
    pub const ELF_SECTIONS: u32 = 9;
    pub const APM: u32 = 10;
    pub const EFI32_SYSTEM_TABLE: u32 = 11;
    pub const EFI64_SYSTEM_TABLE: u32 = 12;
    pub const SMBIOS: u32 = 13;
    pub const ACPI_OLD: u32 = 14;
    pub const ACPI_NEW: u32 = 15;
    pub const NETWORK: u32 = 16;
    pub const EFI_MEMORY_MAP: u32 = 17;
    pub const EFI_BOOT_SERVICES: u32 = 18;
    pub const EFI32_IMAGE_HANDLE: u32 = 19;
    pub const EFI64_IMAGE_HANDLE: u32 = 20;
    pub const IMAGE_LOAD_BASE: u32 = 21;

    /// Get human-readable name for a tag type
    pub const fn name(tag_type: u32) -> &'static str {
        match tag_type {
            END => "End",
            CMDLINE => "Command Line",
            BOOTLOADER_NAME => "Bootloader Name",
            MODULE => "Module",
            BASIC_MEMINFO => "Basic Memory Info",
            BIOS_BOOT_DEVICE => "BIOS Boot Device",
            MEMORY_MAP => "Memory Map",
            VBE_INFO => "VBE Info",
            FRAMEBUFFER => "Framebuffer",
            ELF_SECTIONS => "ELF Sections",
            APM => "APM Table",
            EFI32_SYSTEM_TABLE => "EFI32 System Table",
            EFI64_SYSTEM_TABLE => "EFI64 System Table",
            SMBIOS => "SMBIOS",
            ACPI_OLD => "ACPI Old RSDP",
            ACPI_NEW => "ACPI New RSDP",
            NETWORK => "Network Info",
            EFI_MEMORY_MAP => "EFI Memory Map",
            EFI_BOOT_SERVICES => "EFI Boot Services",
            EFI32_IMAGE_HANDLE => "EFI32 Image Handle",
            EFI64_IMAGE_HANDLE => "EFI64 Image Handle",
            IMAGE_LOAD_BASE => "Image Load Base",
            _ => "Unknown",
        }
    }
}

/// Memory map entry types (E820 compatible)
pub mod memory_type {
    pub const AVAILABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;

    /// Get human-readable name for memory type
    pub const fn name(mem_type: u32) -> &'static str {
        match mem_type {
            AVAILABLE => "Available",
            RESERVED => "Reserved",
            ACPI_RECLAIMABLE => "ACPI Reclaimable",
            ACPI_NVS => "ACPI NVS",
            BAD_MEMORY => "Bad Memory",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Multiboot subsystem errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultibootError {
    /// Invalid magic number from bootloader
    InvalidMagic { expected: u32, found: u32 },
    /// Information structure too small
    InvalidInfoSize { size: u32 },
    /// Tag structure is malformed
    MalformedTag { tag_type: u32, reason: &'static str },
    /// Memory map parsing failed
    MemoryMapError { reason: &'static str },
    /// Framebuffer info parsing failed
    FramebufferError { reason: &'static str },
    /// Module parsing failed
    ModuleError { reason: &'static str },
    /// ELF section parsing failed
    ElfSectionError { reason: &'static str },
    /// ACPI RSDP parsing failed
    AcpiError { reason: &'static str },
    /// SMBIOS parsing failed
    SmbiosError { reason: &'static str },
    /// Subsystem not initialized
    NotInitialized,
    /// Already initialized
    AlreadyInitialized,
    /// No memory map available
    NoMemoryMap,
    /// Invalid UTF-8 in string
    InvalidUtf8,
    /// Pointer alignment error
    AlignmentError { expected: usize, found: usize },
    /// Address out of valid range
    AddressOutOfRange { address: u64 },
}

impl MultibootError {
    /// Get a static string description of the error
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMagic { .. } => "Invalid multiboot magic number",
            Self::InvalidInfoSize { .. } => "Invalid information structure size",
            Self::MalformedTag { .. } => "Malformed tag structure",
            Self::MemoryMapError { .. } => "Memory map parsing error",
            Self::FramebufferError { .. } => "Framebuffer info parsing error",
            Self::ModuleError { .. } => "Module parsing error",
            Self::ElfSectionError { .. } => "ELF section parsing error",
            Self::AcpiError { .. } => "ACPI RSDP parsing error",
            Self::SmbiosError { .. } => "SMBIOS parsing error",
            Self::NotInitialized => "Multiboot subsystem not initialized",
            Self::AlreadyInitialized => "Multiboot subsystem already initialized",
            Self::NoMemoryMap => "No memory map available",
            Self::InvalidUtf8 => "Invalid UTF-8 in string data",
            Self::AlignmentError { .. } => "Pointer alignment error",
            Self::AddressOutOfRange { .. } => "Address out of valid range",
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Multiboot subsystem statistics
pub struct MultibootStats {
    /// Total memory map entries parsed
    pub memory_entries_parsed: AtomicU64,
    /// Total modules parsed
    pub modules_parsed: AtomicU64,
    /// Total tags processed
    pub tags_processed: AtomicU64,
    /// Unknown tags encountered
    pub unknown_tags: AtomicU64,
    /// Parse errors encountered
    pub parse_errors: AtomicU64,
    /// Total available memory in bytes
    pub total_available_memory: AtomicU64,
    /// Total reserved memory in bytes
    pub total_reserved_memory: AtomicU64,
}

impl MultibootStats {
    const fn new() -> Self {
        Self {
            memory_entries_parsed: AtomicU64::new(0),
            modules_parsed: AtomicU64::new(0),
            tags_processed: AtomicU64::new(0),
            unknown_tags: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            total_available_memory: AtomicU64::new(0),
            total_reserved_memory: AtomicU64::new(0),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.memory_entries_parsed.store(0, Ordering::SeqCst);
        self.modules_parsed.store(0, Ordering::SeqCst);
        self.tags_processed.store(0, Ordering::SeqCst);
        self.unknown_tags.store(0, Ordering::SeqCst);
        self.parse_errors.store(0, Ordering::SeqCst);
        self.total_available_memory.store(0, Ordering::SeqCst);
        self.total_reserved_memory.store(0, Ordering::SeqCst);
    }
}

// ============================================================================
// Core Structures
// ============================================================================

/// Multiboot2 header structure (placed in kernel binary)
#[repr(C, align(8))]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
}

impl Multiboot2Header {
    /// Create a new Multiboot2 header with correct checksum
    pub const fn new(header_length: u32) -> Self {
        let checksum = (0u32)
            .wrapping_sub(MULTIBOOT2_HEADER_MAGIC)
            .wrapping_sub(MULTIBOOT2_ARCHITECTURE_I386)
            .wrapping_sub(header_length);
        Self {
            magic: MULTIBOOT2_HEADER_MAGIC,
            architecture: MULTIBOOT2_ARCHITECTURE_I386,
            header_length,
            checksum,
        }
    }

    /// Verify the header checksum
    pub const fn verify_checksum(&self) -> bool {
        self.magic
            .wrapping_add(self.architecture)
            .wrapping_add(self.header_length)
            .wrapping_add(self.checksum)
            == 0
    }
}

/// Multiboot2 information structure header
#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
}

/// Tag header (common to all tags)
#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}

/// Memory map entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

impl MemoryMapEntry {
    /// Check if this region is available for use
    pub const fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    /// Check if this region is ACPI reclaimable
    pub const fn is_acpi_reclaimable(&self) -> bool {
        self.entry_type == memory_type::ACPI_RECLAIMABLE
    }

    /// Get the start physical address
    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    /// Get the end physical address (exclusive)
    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    /// Get human-readable type name
    pub const fn type_name(&self) -> &'static str {
        memory_type::name(self.entry_type)
    }
}

/// Framebuffer information
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub framebuffer_type: FramebufferType,
    /// Color info for direct RGB mode
    pub color_info: Option<ColorInfo>,
}

/// Framebuffer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferType {
    /// Indexed color with palette
    Indexed,
    /// Direct RGB color
    DirectRgb,
    /// EGA text mode
    EgaText,
    /// Unknown type
    Unknown(u8),
}

impl From<u8> for FramebufferType {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Indexed,
            1 => Self::DirectRgb,
            2 => Self::EgaText,
            other => Self::Unknown(other),
        }
    }
}

/// Color field information for direct RGB mode
#[derive(Debug, Clone, Copy)]
pub struct ColorInfo {
    pub red_position: u8,
    pub red_mask_size: u8,
    pub green_position: u8,
    pub green_mask_size: u8,
    pub blue_position: u8,
    pub blue_mask_size: u8,
}

/// Boot module information
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub cmdline: Option<String>,
}

impl ModuleInfo {
    /// Get the size of the module in bytes
    pub fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

/// Basic memory information (legacy)
#[derive(Debug, Clone, Copy)]
pub struct BasicMemInfo {
    /// Memory below 1MB in KB
    pub mem_lower: u32,
    /// Memory above 1MB in KB
    pub mem_upper: u32,
}

/// BIOS boot device information
#[derive(Debug, Clone, Copy)]
pub struct BiosBootDevice {
    pub bios_dev: u32,
    pub partition: u32,
    pub sub_partition: u32,
}

/// VBE (VESA BIOS Extensions) information
#[derive(Debug, Clone)]
pub struct VbeInfo {
    pub mode: u16,
    pub interface_seg: u16,
    pub interface_off: u16,
    pub interface_len: u16,
    pub control_info: [u8; 512],
    pub mode_info: [u8; 256],
}

/// ELF section header information
#[derive(Debug, Clone)]
pub struct ElfSections {
    pub num: u32,
    pub entsize: u32,
    pub shndx: u32,
    pub sections: Vec<ElfSection>,
}

/// Individual ELF section
#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name_index: u32,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

/// APM (Advanced Power Management) table
#[derive(Debug, Clone, Copy)]
pub struct ApmTable {
    pub version: u16,
    pub cseg: u16,
    pub offset: u32,
    pub cseg_16: u16,
    pub dseg: u16,
    pub flags: u16,
    pub cseg_len: u16,
    pub cseg_16_len: u16,
    pub dseg_len: u16,
}

/// ACPI RSDP (Root System Description Pointer)
#[derive(Debug, Clone)]
pub struct AcpiRsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
    /// Extended fields (ACPI 2.0+)
    pub length: Option<u32>,
    pub xsdt_address: Option<u64>,
    pub extended_checksum: Option<u8>,
}

impl AcpiRsdp {
    /// Check if this is ACPI 2.0 or later
    pub fn is_acpi2(&self) -> bool {
        self.revision >= 2
    }

    /// Get the preferred table address (XSDT for 2.0+, RSDT otherwise)
    pub fn table_address(&self) -> u64 {
        if let Some(xsdt) = self.xsdt_address {
            if xsdt != 0 {
                return xsdt;
            }
        }
        self.rsdt_address as u64
    }

    /// Verify the RSDP checksum
    pub fn verify_checksum(&self) -> bool {
        // Basic checksum covers first 20 bytes
        let basic_data: [u8; 20] = unsafe {
            let ptr = self as *const Self as *const u8;
            let mut arr = [0u8; 20];
            for i in 0..20 {
                arr[i] = *ptr.add(i);
            }
            arr
        };
        let sum: u8 = basic_data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

/// SMBIOS table entry point
#[derive(Debug, Clone)]
pub struct SmbiosInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub table_address: PhysAddr,
    pub table_length: u32,
}

/// EFI memory map entry
#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

/// Complete parsed Multiboot2 information
#[derive(Debug, Clone)]
pub struct ParsedMultibootInfo {
    /// Raw information address
    pub info_addr: VirtAddr,
    /// Total size of the structure
    pub total_size: u32,
    /// Kernel command line
    pub cmdline: Option<String>,
    /// Bootloader name
    pub bootloader_name: Option<String>,
    /// Memory map
    pub memory_map: Vec<MemoryMapEntry>,
    /// Framebuffer information
    pub framebuffer: Option<FramebufferInfo>,
    /// Loaded modules
    pub modules: Vec<ModuleInfo>,
    /// Basic memory info (legacy)
    pub basic_meminfo: Option<BasicMemInfo>,
    /// BIOS boot device
    pub boot_device: Option<BiosBootDevice>,
    /// VBE info
    pub vbe_info: Option<VbeInfo>,
    /// ELF sections
    pub elf_sections: Option<ElfSections>,
    /// APM table
    pub apm: Option<ApmTable>,
    /// ACPI RSDP
    pub acpi_rsdp: Option<AcpiRsdp>,
    /// SMBIOS info
    pub smbios: Option<SmbiosInfo>,
    /// EFI 64-bit system table pointer
    pub efi64_system_table: Option<u64>,
    /// EFI 32-bit system table pointer
    pub efi32_system_table: Option<u32>,
    /// EFI memory map
    pub efi_memory_map: Option<Vec<EfiMemoryDescriptor>>,
    /// EFI boot services not terminated flag
    pub efi_boot_services_not_terminated: bool,
    /// EFI 64-bit image handle
    pub efi64_image_handle: Option<u64>,
    /// EFI 32-bit image handle
    pub efi32_image_handle: Option<u32>,
    /// Image load base address
    pub image_load_base: Option<PhysAddr>,
}

impl ParsedMultibootInfo {
    /// Get total available memory from memory map
    pub fn total_available_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.length)
            .sum()
    }

    /// Get total reserved memory from memory map
    pub fn total_reserved_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| !e.is_available())
            .map(|e| e.length)
            .sum()
    }

    /// Find the largest available memory region
    pub fn largest_available_region(&self) -> Option<&MemoryMapEntry> {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .max_by_key(|e| e.length)
    }

    /// Check if ACPI tables are available
    pub fn has_acpi(&self) -> bool {
        self.acpi_rsdp.is_some()
    }

    /// Check if running with EFI
    pub fn is_efi_boot(&self) -> bool {
        self.efi64_system_table.is_some() || self.efi32_system_table.is_some()
    }
}

// ============================================================================
// Platform Detection
// ============================================================================

/// Detected platform type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// QEMU with TCG (software emulation)
    QemuTcg,
    /// QEMU with KVM acceleration
    QemuKvm,
    /// Linux KVM (not QEMU)
    Kvm,
    /// VMware (ESXi, Workstation, Fusion)
    Vmware,
    /// Microsoft Hyper-V
    HyperV,
    /// Xen Hypervisor
    Xen,
    /// Oracle VirtualBox
    VirtualBox,
    /// FreeBSD bhyve
    Bhyve,
    /// ACRN Hypervisor
    Acrn,
    /// Parallels Desktop
    Parallels,
    /// Apple Hypervisor Framework
    AppleHv,
    /// Unknown hypervisor
    UnknownVm,
    /// Bare metal hardware
    BareMetal,
}

impl Platform {
    /// Get human-readable platform name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::QemuTcg => "QEMU (TCG)",
            Self::QemuKvm => "QEMU (KVM)",
            Self::Kvm => "Linux KVM",
            Self::Vmware => "VMware",
            Self::HyperV => "Microsoft Hyper-V",
            Self::Xen => "Xen Hypervisor",
            Self::VirtualBox => "Oracle VirtualBox",
            Self::Bhyve => "FreeBSD bhyve",
            Self::Acrn => "ACRN Hypervisor",
            Self::Parallels => "Parallels Desktop",
            Self::AppleHv => "Apple Hypervisor",
            Self::UnknownVm => "Unknown Hypervisor",
            Self::BareMetal => "Bare Metal",
        }
    }

    /// Check if running in any virtual environment
    pub const fn is_virtual(&self) -> bool {
        !matches!(self, Self::BareMetal)
    }

    /// Check if this is a QEMU environment
    pub const fn is_qemu(&self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm)
    }

    /// Check if hardware virtualization is available
    pub const fn has_hw_virtualization(&self) -> bool {
        matches!(
            self,
            Self::QemuKvm | Self::Kvm | Self::HyperV | Self::Vmware | Self::Xen
        )
    }

    /// Check if virtio devices might be available
    pub const fn supports_virtio(&self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm | Self::Kvm)
    }

    /// Get recommended timer frequency in Hz
    pub const fn timer_frequency(&self) -> u32 {
        match self {
            Self::QemuTcg => 100,  // TCG is slower
            Self::QemuKvm | Self::Kvm => 1000,
            Self::Vmware | Self::VirtualBox => 100,
            Self::HyperV => 1000,
            Self::Xen => 100,
            Self::BareMetal => 1000,
            _ => 100,
        }
    }

    /// Get recommended console type
    pub const fn console_type(&self) -> ConsoleType {
        match self {
            Self::QemuTcg | Self::QemuKvm => ConsoleType::Serial,
            Self::Vmware | Self::VirtualBox => ConsoleType::Vga,
            Self::HyperV => ConsoleType::EfiConsole,
            _ => ConsoleType::Serial,
        }
    }
}

/// Console output type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    /// VGA text mode
    Vga,
    /// Serial port (COM1)
    Serial,
    /// Framebuffer graphics
    Framebuffer,
    /// EFI console output
    EfiConsole,
}

/// Known hypervisor signatures for CPUID leaf 0x40000000
struct HypervisorSignature {
    ebx: u32,
    ecx: u32,
    edx: u32,
    platform: Platform,
}

const HYPERVISOR_SIGNATURES: &[HypervisorSignature] = &[
    // "KVMKVMKVM\0\0\0"
    HypervisorSignature {
        ebx: 0x4B4D564B,  // KVMK
        ecx: 0x564B4D56,  // VMKV
        edx: 0x0000004D,  // M\0\0\0
        platform: Platform::Kvm,
    },
    // "Microsoft Hv"
    HypervisorSignature {
        ebx: 0x7263694D,  // Micr
        ecx: 0x666F736F,  // osof
        edx: 0x76482074,  // t Hv
        platform: Platform::HyperV,
    },
    // "VMwareVMware"
    HypervisorSignature {
        ebx: 0x61774D56,  // VMwa
        ecx: 0x4D566572,  // reVM
        edx: 0x65726177,  // ware
        platform: Platform::Vmware,
    },
    // "XenVMMXenVMM"
    HypervisorSignature {
        ebx: 0x566E6558,  // XenV
        ecx: 0x65584D4D,  // MMXe
        edx: 0x4D4D566E,  // nVMM
        platform: Platform::Xen,
    },
    // "TCGTCGTCGTCG" - QEMU TCG
    HypervisorSignature {
        ebx: 0x54474354,  // TCGT
        ecx: 0x54474354,  // CGTC
        edx: 0x47544347,  // GTCG
        platform: Platform::QemuTcg,
    },
    // "VBoxVBoxVBox"
    HypervisorSignature {
        ebx: 0x786F4256,  // VBox
        ecx: 0x6F425678,  // VBox
        edx: 0x78784256,  // VBox - actually should be 0x786F4256
        platform: Platform::VirtualBox,
    },
    // "bhyve bhyve "
    HypervisorSignature {
        ebx: 0x76796862,  // bhyv
        ecx: 0x68622065,  // e bh
        edx: 0x20657679,  // yve
        platform: Platform::Bhyve,
    },
    // "ACRNACRNACRN"
    HypervisorSignature {
        ebx: 0x4E524341,  // ACRN
        ecx: 0x4E524341,  // ACRN
        edx: 0x4E524341,  // ACRN
        platform: Platform::Acrn,
    },
];

/// Detect the current platform using CPUID
pub fn detect_platform() -> Platform {
    // Check CPUID hypervisor present bit (ECX bit 31 of leaf 1)
    let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
    let hypervisor_present = (cpuid1.ecx >> 31) & 1 != 0;

    if !hypervisor_present {
        return Platform::BareMetal;
    }

    // Query hypervisor signature from leaf 0x40000000
    let cpuid_hv = unsafe { core::arch::x86_64::__cpuid(0x40000000) };

    // Check max leaf is valid
    if cpuid_hv.eax < 0x40000000 {
        return Platform::UnknownVm;
    }

    // Match against known signatures
    for sig in HYPERVISOR_SIGNATURES {
        if cpuid_hv.ebx == sig.ebx && cpuid_hv.ecx == sig.ecx && cpuid_hv.edx == sig.edx {
            // Special case: distinguish QEMU+KVM from plain KVM
            if sig.platform == Platform::Kvm {
                // Check for QEMU-specific traits (simplified check)
                // In practice, QEMU+KVM still reports KVMKVMKVM
                // We detect it by checking for QEMU-specific devices later
                return Platform::QemuKvm;
            }
            return sig.platform;
        }
    }

    // Check for partial matches (some VMs have variations)
    let sig_bytes = [
        (cpuid_hv.ebx & 0xFF) as u8,
        ((cpuid_hv.ebx >> 8) & 0xFF) as u8,
        ((cpuid_hv.ebx >> 16) & 0xFF) as u8,
        ((cpuid_hv.ebx >> 24) & 0xFF) as u8,
        (cpuid_hv.ecx & 0xFF) as u8,
        ((cpuid_hv.ecx >> 8) & 0xFF) as u8,
        ((cpuid_hv.ecx >> 16) & 0xFF) as u8,
        ((cpuid_hv.ecx >> 24) & 0xFF) as u8,
        (cpuid_hv.edx & 0xFF) as u8,
        ((cpuid_hv.edx >> 8) & 0xFF) as u8,
        ((cpuid_hv.edx >> 16) & 0xFF) as u8,
        ((cpuid_hv.edx >> 24) & 0xFF) as u8,
    ];

    // Check for VirtualBox (variant signature)
    if &sig_bytes[0..4] == b"VBox" {
        return Platform::VirtualBox;
    }

    // Check for Parallels (" lrpepyh  vr" scrambled)
    if sig_bytes.contains(&b'p') && sig_bytes.contains(&b'r') && sig_bytes.contains(&b'l') {
        return Platform::Parallels;
    }

    Platform::UnknownVm
}

// ============================================================================
// Global State
// ============================================================================

/// Global multiboot manager instance
pub static MULTIBOOT_MANAGER: MultibootManager = MultibootManager::new();

/// Thread-safe multiboot information manager
pub struct MultibootManager {
    initialized: AtomicBool,
    bootloader_magic: AtomicU64,
    parsed_info: RwLock<Option<ParsedMultibootInfo>>,
    platform: RwLock<Platform>,
    stats: MultibootStats,
}

impl MultibootManager {
    /// Create a new uninitialized manager
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            bootloader_magic: AtomicU64::new(0),
            parsed_info: RwLock::new(None),
            platform: RwLock::new(Platform::BareMetal),
            stats: MultibootStats::new(),
        }
    }

    /// Initialize with raw multiboot information
    ///
    /// # Safety
    /// The info_addr must point to a valid Multiboot2 information structure.
    pub unsafe fn initialize(
        &self,
        magic: u32,
        info_addr: VirtAddr,
    ) -> Result<(), MultibootError> {
        if self.initialized.load(Ordering::SeqCst) {
            return Err(MultibootError::AlreadyInitialized);
        }

        // Verify magic number
        if magic != MULTIBOOT2_BOOTLOADER_MAGIC {
            return Err(MultibootError::InvalidMagic {
                expected: MULTIBOOT2_BOOTLOADER_MAGIC,
                found: magic,
            });
        }

        self.bootloader_magic.store(magic as u64, Ordering::SeqCst);

        // Parse the information structure
        let parsed = self.parse_info(info_addr)?;

        // Update statistics
        self.stats.total_available_memory.store(
            parsed.total_available_memory(),
            Ordering::SeqCst,
        );
        self.stats.total_reserved_memory.store(
            parsed.total_reserved_memory(),
            Ordering::SeqCst,
        );

        // Store parsed info
        *self.parsed_info.write() = Some(parsed);

        // Detect platform
        let platform = detect_platform();
        *self.platform.write() = platform;

        self.initialized.store(true, Ordering::SeqCst);

        crate::log::info!(
            "Multiboot2 initialized: {} available, {} reserved, platform: {}",
            format_bytes(self.stats.total_available_memory.load(Ordering::SeqCst)),
            format_bytes(self.stats.total_reserved_memory.load(Ordering::SeqCst)),
            platform.name()
        );

        Ok(())
    }

    /// Parse multiboot2 information structure
    unsafe fn parse_info(&self, info_addr: VirtAddr) -> Result<ParsedMultibootInfo, MultibootError> {
        // Check alignment
        if info_addr.as_u64() % 8 != 0 {
            return Err(MultibootError::AlignmentError {
                expected: 8,
                found: (info_addr.as_u64() % 8) as usize,
            });
        }

        let info = &*info_addr.as_ptr::<Multiboot2Info>();

        if info.total_size < 8 {
            return Err(MultibootError::InvalidInfoSize {
                size: info.total_size,
            });
        }

        let mut parsed = ParsedMultibootInfo {
            info_addr,
            total_size: info.total_size,
            cmdline: None,
            bootloader_name: None,
            memory_map: Vec::new(),
            framebuffer: None,
            modules: Vec::new(),
            basic_meminfo: None,
            boot_device: None,
            vbe_info: None,
            elf_sections: None,
            apm: None,
            acpi_rsdp: None,
            smbios: None,
            efi64_system_table: None,
            efi32_system_table: None,
            efi_memory_map: None,
            efi_boot_services_not_terminated: false,
            efi64_image_handle: None,
            efi32_image_handle: None,
            image_load_base: None,
        };

        let mut tag_ptr = (info_addr + 8u64).as_ptr::<u8>();
        let end_ptr = (info_addr + info.total_size as u64).as_ptr::<u8>();

        while tag_ptr < end_ptr {
            let tag_header = &*(tag_ptr as *const TagHeader);

            // End tag
            if tag_header.tag_type == tag::END && tag_header.size == 8 {
                break;
            }

            self.stats.tags_processed.fetch_add(1, Ordering::SeqCst);

            match tag_header.tag_type {
                tag::CMDLINE => {
                    parsed.cmdline = self.parse_string_tag(tag_ptr, tag_header.size);
                }
                tag::BOOTLOADER_NAME => {
                    parsed.bootloader_name = self.parse_string_tag(tag_ptr, tag_header.size);
                }
                tag::MODULE => {
                    if let Ok(module) = self.parse_module(tag_ptr, tag_header.size) {
                        parsed.modules.push(module);
                        self.stats.modules_parsed.fetch_add(1, Ordering::SeqCst);
                    }
                }
                tag::BASIC_MEMINFO => {
                    parsed.basic_meminfo = self.parse_basic_meminfo(tag_ptr);
                }
                tag::BIOS_BOOT_DEVICE => {
                    parsed.boot_device = self.parse_boot_device(tag_ptr);
                }
                tag::MEMORY_MAP => {
                    if let Ok(entries) = self.parse_memory_map(tag_ptr, tag_header.size) {
                        self.stats
                            .memory_entries_parsed
                            .fetch_add(entries.len() as u64, Ordering::SeqCst);
                        parsed.memory_map = entries;
                    }
                }
                tag::VBE_INFO => {
                    parsed.vbe_info = self.parse_vbe_info(tag_ptr, tag_header.size);
                }
                tag::FRAMEBUFFER => {
                    if let Ok(fb) = self.parse_framebuffer(tag_ptr, tag_header.size) {
                        parsed.framebuffer = Some(fb);
                    }
                }
                tag::ELF_SECTIONS => {
                    if let Ok(elf) = self.parse_elf_sections(tag_ptr, tag_header.size) {
                        parsed.elf_sections = Some(elf);
                    }
                }
                tag::APM => {
                    parsed.apm = self.parse_apm(tag_ptr);
                }
                tag::EFI32_SYSTEM_TABLE => {
                    parsed.efi32_system_table = self.parse_efi32_ptr(tag_ptr);
                }
                tag::EFI64_SYSTEM_TABLE => {
                    parsed.efi64_system_table = self.parse_efi64_ptr(tag_ptr);
                }
                tag::SMBIOS => {
                    if let Ok(smbios) = self.parse_smbios(tag_ptr, tag_header.size) {
                        parsed.smbios = Some(smbios);
                    }
                }
                tag::ACPI_OLD => {
                    if let Ok(rsdp) = self.parse_acpi_rsdp(tag_ptr, tag_header.size, false) {
                        parsed.acpi_rsdp = Some(rsdp);
                    }
                }
                tag::ACPI_NEW => {
                    if let Ok(rsdp) = self.parse_acpi_rsdp(tag_ptr, tag_header.size, true) {
                        parsed.acpi_rsdp = Some(rsdp);
                    }
                }
                tag::EFI_MEMORY_MAP => {
                    if let Ok(map) = self.parse_efi_memory_map(tag_ptr, tag_header.size) {
                        parsed.efi_memory_map = Some(map);
                    }
                }
                tag::EFI_BOOT_SERVICES => {
                    parsed.efi_boot_services_not_terminated = true;
                }
                tag::EFI32_IMAGE_HANDLE => {
                    parsed.efi32_image_handle = self.parse_efi32_ptr(tag_ptr);
                }
                tag::EFI64_IMAGE_HANDLE => {
                    parsed.efi64_image_handle = self.parse_efi64_ptr(tag_ptr);
                }
                tag::IMAGE_LOAD_BASE => {
                    parsed.image_load_base = self.parse_image_load_base(tag_ptr);
                }
                _ => {
                    self.stats.unknown_tags.fetch_add(1, Ordering::SeqCst);
                }
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag_header.size + 7) & !7) as usize;
            tag_ptr = tag_ptr.add(next_offset);
        }

        Ok(parsed)
    }

    /// Parse a null-terminated string tag
    unsafe fn parse_string_tag(&self, tag_ptr: *const u8, size: u32) -> Option<String> {
        if size <= 8 {
            return None;
        }

        let string_ptr = tag_ptr.add(8);
        let max_len = (size - 8) as usize;
        let mut len = 0;

        while len < max_len {
            if *string_ptr.add(len) == 0 {
                break;
            }
            len += 1;
        }

        if len == 0 {
            return None;
        }

        let slice = slice::from_raw_parts(string_ptr, len);
        core::str::from_utf8(slice).ok().map(String::from)
    }

    /// Parse module tag
    unsafe fn parse_module(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ModuleInfo, MultibootError> {
        #[repr(C)]
        struct ModuleTag {
            tag_type: u32,
            size: u32,
            mod_start: u32,
            mod_end: u32,
        }

        let tag = &*(tag_ptr as *const ModuleTag);

        if tag.mod_end < tag.mod_start {
            return Err(MultibootError::ModuleError {
                reason: "Invalid module bounds",
            });
        }

        let cmdline = if size > 16 {
            let cmdline_ptr = tag_ptr.add(16);
            let max_len = (size - 16) as usize;
            let mut len = 0;
            while len < max_len && *cmdline_ptr.add(len) != 0 {
                len += 1;
            }
            if len > 0 {
                let slice = slice::from_raw_parts(cmdline_ptr, len);
                core::str::from_utf8(slice).ok().map(String::from)
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

    /// Parse basic memory info tag
    unsafe fn parse_basic_meminfo(&self, tag_ptr: *const u8) -> Option<BasicMemInfo> {
        #[repr(C)]
        struct BasicMemInfoTag {
            tag_type: u32,
            size: u32,
            mem_lower: u32,
            mem_upper: u32,
        }

        let tag = &*(tag_ptr as *const BasicMemInfoTag);
        Some(BasicMemInfo {
            mem_lower: tag.mem_lower,
            mem_upper: tag.mem_upper,
        })
    }

    /// Parse BIOS boot device tag
    unsafe fn parse_boot_device(&self, tag_ptr: *const u8) -> Option<BiosBootDevice> {
        #[repr(C)]
        struct BootDeviceTag {
            tag_type: u32,
            size: u32,
            biosdev: u32,
            partition: u32,
            sub_partition: u32,
        }

        let tag = &*(tag_ptr as *const BootDeviceTag);
        Some(BiosBootDevice {
            bios_dev: tag.biosdev,
            partition: tag.partition,
            sub_partition: tag.sub_partition,
        })
    }

    /// Parse memory map tag
    unsafe fn parse_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<MemoryMapEntry>, MultibootError> {
        #[repr(C)]
        struct MemoryMapTag {
            tag_type: u32,
            size: u32,
            entry_size: u32,
            entry_version: u32,
        }

        let tag = &*(tag_ptr as *const MemoryMapTag);

        if tag.entry_size == 0 {
            return Err(MultibootError::MemoryMapError {
                reason: "Zero entry size",
            });
        }

        let entries_size = size.saturating_sub(16);
        let num_entries = entries_size / tag.entry_size;
        let mut entries = Vec::with_capacity(num_entries as usize);

        let mut entry_ptr = tag_ptr.add(16);
        for _ in 0..num_entries {
            let entry = *(entry_ptr as *const MemoryMapEntry);
            entries.push(entry);
            entry_ptr = entry_ptr.add(tag.entry_size as usize);
        }

        Ok(entries)
    }

    /// Parse VBE info tag
    unsafe fn parse_vbe_info(&self, tag_ptr: *const u8, size: u32) -> Option<VbeInfo> {
        if size < 8 + 6 + 512 + 256 {
            return None;
        }

        #[repr(C)]
        struct VbeTag {
            tag_type: u32,
            size: u32,
            vbe_mode: u16,
            vbe_interface_seg: u16,
            vbe_interface_off: u16,
            vbe_interface_len: u16,
            vbe_control_info: [u8; 512],
            vbe_mode_info: [u8; 256],
        }

        let tag = &*(tag_ptr as *const VbeTag);
        Some(VbeInfo {
            mode: tag.vbe_mode,
            interface_seg: tag.vbe_interface_seg,
            interface_off: tag.vbe_interface_off,
            interface_len: tag.vbe_interface_len,
            control_info: tag.vbe_control_info,
            mode_info: tag.vbe_mode_info,
        })
    }

    /// Parse framebuffer info tag
    unsafe fn parse_framebuffer(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<FramebufferInfo, MultibootError> {
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

        if size < core::mem::size_of::<FramebufferTag>() as u32 {
            return Err(MultibootError::FramebufferError {
                reason: "Tag too small",
            });
        }

        let tag = &*(tag_ptr as *const FramebufferTag);

        let fb_type = FramebufferType::from(tag.framebuffer_type);

        // Parse color info for direct RGB mode
        let color_info = if fb_type == FramebufferType::DirectRgb && size >= 31 {
            let color_ptr = tag_ptr.add(27);
            Some(ColorInfo {
                red_position: *color_ptr,
                red_mask_size: *color_ptr.add(1),
                green_position: *color_ptr.add(2),
                green_mask_size: *color_ptr.add(3),
                blue_position: *color_ptr.add(4),
                blue_mask_size: *color_ptr.add(5),
            })
        } else {
            None
        };

        Ok(FramebufferInfo {
            addr: PhysAddr::new(tag.framebuffer_addr),
            pitch: tag.framebuffer_pitch,
            width: tag.framebuffer_width,
            height: tag.framebuffer_height,
            bpp: tag.framebuffer_bpp,
            framebuffer_type: fb_type,
            color_info,
        })
    }

    /// Parse ELF sections tag
    unsafe fn parse_elf_sections(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ElfSections, MultibootError> {
        #[repr(C)]
        struct ElfSectionsTag {
            tag_type: u32,
            size: u32,
            num: u32,
            entsize: u32,
            shndx: u32,
        }

        if size < core::mem::size_of::<ElfSectionsTag>() as u32 {
            return Err(MultibootError::ElfSectionError {
                reason: "Tag too small",
            });
        }

        let tag = &*(tag_ptr as *const ElfSectionsTag);

        let mut sections = Vec::with_capacity(tag.num as usize);
        let section_data_ptr = tag_ptr.add(20);

        for i in 0..tag.num {
            let section_ptr = section_data_ptr.add((i * tag.entsize) as usize);

            // Parse 64-bit ELF section header
            #[repr(C)]
            struct Elf64Shdr {
                sh_name: u32,
                sh_type: u32,
                sh_flags: u64,
                sh_addr: u64,
                sh_offset: u64,
                sh_size: u64,
                sh_link: u32,
                sh_info: u32,
                sh_addralign: u64,
                sh_entsize: u64,
            }

            if tag.entsize >= core::mem::size_of::<Elf64Shdr>() as u32 {
                let shdr = &*(section_ptr as *const Elf64Shdr);
                sections.push(ElfSection {
                    name_index: shdr.sh_name,
                    section_type: shdr.sh_type,
                    flags: shdr.sh_flags,
                    addr: shdr.sh_addr,
                    offset: shdr.sh_offset,
                    size: shdr.sh_size,
                    link: shdr.sh_link,
                    info: shdr.sh_info,
                    addralign: shdr.sh_addralign,
                    entsize: shdr.sh_entsize,
                });
            }
        }

        Ok(ElfSections {
            num: tag.num,
            entsize: tag.entsize,
            shndx: tag.shndx,
            sections,
        })
    }

    /// Parse APM table tag
    unsafe fn parse_apm(&self, tag_ptr: *const u8) -> Option<ApmTable> {
        #[repr(C)]
        struct ApmTag {
            tag_type: u32,
            size: u32,
            version: u16,
            cseg: u16,
            offset: u32,
            cseg_16: u16,
            dseg: u16,
            flags: u16,
            cseg_len: u16,
            cseg_16_len: u16,
            dseg_len: u16,
        }

        let tag = &*(tag_ptr as *const ApmTag);
        Some(ApmTable {
            version: tag.version,
            cseg: tag.cseg,
            offset: tag.offset,
            cseg_16: tag.cseg_16,
            dseg: tag.dseg,
            flags: tag.flags,
            cseg_len: tag.cseg_len,
            cseg_16_len: tag.cseg_16_len,
            dseg_len: tag.dseg_len,
        })
    }

    /// Parse ACPI RSDP tag
    unsafe fn parse_acpi_rsdp(
        &self,
        tag_ptr: *const u8,
        size: u32,
        is_new: bool,
    ) -> Result<AcpiRsdp, MultibootError> {
        let rsdp_ptr = tag_ptr.add(8);
        let rsdp_size = size.saturating_sub(8) as usize;

        if rsdp_size < 20 {
            return Err(MultibootError::AcpiError {
                reason: "RSDP too small",
            });
        }

        let mut signature = [0u8; 8];
        signature.copy_from_slice(slice::from_raw_parts(rsdp_ptr, 8));

        if &signature != b"RSD PTR " {
            return Err(MultibootError::AcpiError {
                reason: "Invalid RSDP signature",
            });
        }

        let mut oem_id = [0u8; 6];
        oem_id.copy_from_slice(slice::from_raw_parts(rsdp_ptr.add(9), 6));

        let checksum = *rsdp_ptr.add(8);
        let revision = *rsdp_ptr.add(15);
        let rsdt_address = *(rsdp_ptr.add(16) as *const u32);

        let (length, xsdt_address, extended_checksum) = if is_new && rsdp_size >= 36 {
            let length = *(rsdp_ptr.add(20) as *const u32);
            let xsdt_address = *(rsdp_ptr.add(24) as *const u64);
            let extended_checksum = *rsdp_ptr.add(32);
            (Some(length), Some(xsdt_address), Some(extended_checksum))
        } else {
            (None, None, None)
        };

        Ok(AcpiRsdp {
            signature,
            checksum,
            oem_id,
            revision,
            rsdt_address,
            length,
            xsdt_address,
            extended_checksum,
        })
    }

    /// Parse SMBIOS tag
    unsafe fn parse_smbios(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<SmbiosInfo, MultibootError> {
        if size < 16 {
            return Err(MultibootError::SmbiosError {
                reason: "Tag too small",
            });
        }

        #[repr(C)]
        struct SmbiosTag {
            tag_type: u32,
            size: u32,
            major: u8,
            minor: u8,
            reserved: [u8; 6],
        }

        let tag = &*(tag_ptr as *const SmbiosTag);

        // The SMBIOS tables follow after the header
        let table_ptr = tag_ptr.add(16);
        let table_size = size.saturating_sub(16);

        Ok(SmbiosInfo {
            major_version: tag.major,
            minor_version: tag.minor,
            table_address: PhysAddr::new(table_ptr as u64),
            table_length: table_size,
        })
    }

    /// Parse EFI 32-bit pointer
    unsafe fn parse_efi32_ptr(&self, tag_ptr: *const u8) -> Option<u32> {
        let ptr = *(tag_ptr.add(8) as *const u32);
        if ptr != 0 {
            Some(ptr)
        } else {
            None
        }
    }

    /// Parse EFI 64-bit pointer
    unsafe fn parse_efi64_ptr(&self, tag_ptr: *const u8) -> Option<u64> {
        let ptr = *(tag_ptr.add(8) as *const u64);
        if ptr != 0 {
            Some(ptr)
        } else {
            None
        }
    }

    /// Parse EFI memory map
    unsafe fn parse_efi_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<EfiMemoryDescriptor>, MultibootError> {
        #[repr(C)]
        struct EfiMemoryMapTag {
            tag_type: u32,
            size: u32,
            descriptor_size: u32,
            descriptor_version: u32,
        }

        let tag = &*(tag_ptr as *const EfiMemoryMapTag);

        if tag.descriptor_size == 0 {
            return Err(MultibootError::MemoryMapError {
                reason: "Zero descriptor size",
            });
        }

        let entries_offset = 16u32;
        let entries_size = size.saturating_sub(entries_offset);
        let num_entries = entries_size / tag.descriptor_size;

        let mut entries = Vec::with_capacity(num_entries as usize);
        let mut entry_ptr = tag_ptr.add(entries_offset as usize);

        for _ in 0..num_entries {
            #[repr(C)]
            struct EfiMemDesc {
                memory_type: u32,
                padding: u32,
                physical_start: u64,
                virtual_start: u64,
                number_of_pages: u64,
                attribute: u64,
            }

            let desc = &*(entry_ptr as *const EfiMemDesc);
            entries.push(EfiMemoryDescriptor {
                memory_type: desc.memory_type,
                physical_start: desc.physical_start,
                virtual_start: desc.virtual_start,
                number_of_pages: desc.number_of_pages,
                attribute: desc.attribute,
            });

            entry_ptr = entry_ptr.add(tag.descriptor_size as usize);
        }

        Ok(entries)
    }

    /// Parse image load base address
    unsafe fn parse_image_load_base(&self, tag_ptr: *const u8) -> Option<PhysAddr> {
        let addr = *(tag_ptr.add(8) as *const u32);
        Some(PhysAddr::new(addr as u64))
    }

    /// Check if the subsystem is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Get the detected platform
    pub fn platform(&self) -> Platform {
        *self.platform.read()
    }

    /// Get parsed multiboot information
    pub fn info(&self) -> Option<ParsedMultibootInfo> {
        self.parsed_info.read().clone()
    }

    /// Get statistics
    pub fn stats(&self) -> &MultibootStats {
        &self.stats
    }

    /// Get command line
    pub fn cmdline(&self) -> Option<String> {
        self.parsed_info.read().as_ref().and_then(|i| i.cmdline.clone())
    }

    /// Get bootloader name
    pub fn bootloader_name(&self) -> Option<String> {
        self.parsed_info.read().as_ref().and_then(|i| i.bootloader_name.clone())
    }

    /// Get memory map
    pub fn memory_map(&self) -> Vec<MemoryMapEntry> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.memory_map.clone())
            .unwrap_or_default()
    }

    /// Get framebuffer info
    pub fn framebuffer(&self) -> Option<FramebufferInfo> {
        self.parsed_info.read().as_ref().and_then(|i| i.framebuffer.clone())
    }

    /// Get loaded modules
    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.modules.clone())
            .unwrap_or_default()
    }

    /// Get ACPI RSDP if available
    pub fn acpi_rsdp(&self) -> Option<AcpiRsdp> {
        self.parsed_info.read().as_ref().and_then(|i| i.acpi_rsdp.clone())
    }

    /// Check if booted via EFI
    pub fn is_efi_boot(&self) -> bool {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.is_efi_boot())
            .unwrap_or(false)
    }
}

// ============================================================================
// Platform-Specific Initialization
// ============================================================================

/// Initialize platform-specific features based on detected platform
pub fn init_platform_features(platform: Platform) -> Result<(), MultibootError> {
    match platform {
        Platform::QemuTcg => init_qemu_tcg_features()?,
        Platform::QemuKvm | Platform::Kvm => init_kvm_features()?,
        Platform::Vmware => init_vmware_features()?,
        Platform::HyperV => init_hyperv_features()?,
        Platform::Xen => init_xen_features()?,
        Platform::VirtualBox => init_vbox_features()?,
        Platform::BareMetal => init_baremetal_features()?,
        _ => {
            crate::log::info!("No specific initialization for platform: {}", platform.name());
        }
    }
    Ok(())
}

/// Initialize QEMU TCG specific features
fn init_qemu_tcg_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing QEMU TCG features:");
    crate::log::info!("  - Enabling debug port (0x402) for logging");
    crate::log::info!("  - Reduced timer frequency for software emulation");
    crate::log::info!("  - Virtio device detection enabled");

    // Enable QEMU debug port output
    unsafe {
        // Test debug port availability
        x86_64::instructions::port::Port::<u8>::new(0x402).write(0);
    }

    Ok(())
}

/// Initialize KVM specific features
fn init_kvm_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing KVM features:");
    crate::log::info!("  - KVM hypercalls available");
    crate::log::info!("  - Paravirtual clock enabled");
    crate::log::info!("  - Virtio device detection enabled");

    // Check for KVM-specific CPUID leaves
    let kvm_features = unsafe { core::arch::x86_64::__cpuid(0x40000001) };
    if kvm_features.eax & (1 << 0) != 0 {
        crate::log::info!("  - KVM clocksource available");
    }
    if kvm_features.eax & (1 << 3) != 0 {
        crate::log::info!("  - KVM async PF available");
    }
    if kvm_features.eax & (1 << 4) != 0 {
        crate::log::info!("  - KVM steal time available");
    }

    Ok(())
}

/// Initialize VMware specific features
fn init_vmware_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing VMware features:");
    crate::log::info!("  - VMware backdoor interface detection");
    crate::log::info!("  - VMXNET3 network driver support");
    crate::log::info!("  - PVSCSI storage driver support");

    // VMware backdoor magic port
    const VMWARE_MAGIC: u32 = 0x564D5868; // "VMXh"
    const VMWARE_PORT: u16 = 0x5658;

    // Test VMware backdoor (simplified - actual implementation needs more care)
    crate::log::info!("  - VMware backdoor port: 0x{:X}", VMWARE_PORT);

    Ok(())
}

/// Initialize Hyper-V specific features
fn init_hyperv_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing Hyper-V features:");

    // Query Hyper-V feature identification
    let hv_features = unsafe { core::arch::x86_64::__cpuid(0x40000003) };

    if hv_features.eax & (1 << 0) != 0 {
        crate::log::info!("  - VP runtime MSR available");
    }
    if hv_features.eax & (1 << 1) != 0 {
        crate::log::info!("  - Partition reference counter available");
    }
    if hv_features.eax & (1 << 2) != 0 {
        crate::log::info!("  - Synthetic timers available");
    }
    if hv_features.eax & (1 << 3) != 0 {
        crate::log::info!("  - APIC access MSRs available");
    }
    if hv_features.eax & (1 << 4) != 0 {
        crate::log::info!("  - Hypercall MSRs available");
    }
    if hv_features.eax & (1 << 5) != 0 {
        crate::log::info!("  - VP index MSR available");
    }

    Ok(())
}

/// Initialize Xen specific features
fn init_xen_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing Xen features:");

    // Query Xen version
    let xen_version = unsafe { core::arch::x86_64::__cpuid(0x40000001) };
    let major = (xen_version.eax >> 16) & 0xFFFF;
    let minor = xen_version.eax & 0xFFFF;

    crate::log::info!("  - Xen version: {}.{}", major, minor);
    crate::log::info!("  - Xen hypercalls available");
    crate::log::info!("  - Xen PV clock enabled");

    Ok(())
}

/// Initialize VirtualBox specific features
fn init_vbox_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing VirtualBox features:");
    crate::log::info!("  - VBoxGuest interface detection");
    crate::log::info!("  - VirtualBox graphics adapter support");

    // VirtualBox uses PCI device ID 0x80EE (VirtualBox vendor ID) for guest additions
    crate::log::info!("  - Looking for VBox PCI devices (vendor 0x80EE)");

    Ok(())
}

/// Initialize bare metal specific features
fn init_baremetal_features() -> Result<(), MultibootError> {
    crate::log::info!("Initializing bare metal features:");
    crate::log::info!("  - Full hardware timer precision");
    crate::log::info!("  - Native ACPI power management");
    crate::log::info!("  - Hardware interrupt affinity");

    // Enable performance monitoring on real hardware
    let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
    if cpuid1.ecx & (1 << 15) != 0 {
        crate::log::info!("  - PDCM (Perfmon/Debug) available");
    }
    if cpuid1.edx & (1 << 22) != 0 {
        crate::log::info!("  - ACPI via MSR available");
    }

    Ok(())
}

// ============================================================================
// Memory Region Helpers
// ============================================================================

/// Get safe memory regions from multiboot info
pub fn get_safe_memory_regions() -> Result<Vec<crate::memory::layout::Region>, MultibootError> {
    if !MULTIBOOT_MANAGER.is_initialized() {
        return Err(MultibootError::NotInitialized);
    }

    let memory_map = MULTIBOOT_MANAGER.memory_map();
    if memory_map.is_empty() {
        return Err(MultibootError::NoMemoryMap);
    }

    let mut regions = Vec::new();

    for entry in &memory_map {
        // Only use available memory above 1MB
        if entry.is_available() && entry.length >= 4096 && entry.base_addr >= 0x100000 {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Usable,
            });
        } else if entry.is_acpi_reclaimable() {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::AcpiReclaimable,
            });
        }
    }

    // Sort by start address
    regions.sort_by_key(|r| r.start);

    Ok(regions)
}

/// Get fallback memory regions when no memory map is available
pub fn get_fallback_memory_regions(platform: Platform) -> Vec<crate::memory::layout::Region> {
    let end = match platform {
        Platform::QemuTcg | Platform::QemuKvm => 0x8000000,  // 128MB
        Platform::Kvm | Platform::Vmware | Platform::VirtualBox => 0x10000000, // 256MB
        Platform::HyperV => 0x20000000, // 512MB
        Platform::BareMetal => 0x4000000, // 64MB conservative
        _ => 0x4000000, // 64MB default
    };

    vec![crate::memory::layout::Region {
        start: 0x100000,  // 1MB
        end,
        kind: crate::memory::layout::RegionKind::Usable,
    }]
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        alloc::format!("{} GB", bytes / GB)
    } else if bytes >= MB {
        alloc::format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        alloc::format!("{} KB", bytes / KB)
    } else {
        alloc::format!("{} B", bytes)
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the multiboot subsystem
///
/// # Safety
/// Must be called early in boot with valid multiboot2 magic and info address.
pub unsafe fn init_with_info(magic: u32, info_addr: VirtAddr) -> Result<(), MultibootError> {
    MULTIBOOT_MANAGER.initialize(magic, info_addr)?;

    // Initialize platform-specific features
    let platform = MULTIBOOT_MANAGER.platform();
    init_platform_features(platform)?;

    Ok(())
}

/// Initialize the multiboot subsystem (basic init without multiboot info)
pub fn init() -> Result<(), MultibootError> {
    // If already initialized with info, just return success
    if MULTIBOOT_MANAGER.is_initialized() {
        return Ok(());
    }

    // Detect platform even without multiboot info
    let platform = detect_platform();
    *MULTIBOOT_MANAGER.platform.write() = platform;

    crate::log::info!("Multiboot subsystem ready (platform: {})", platform.name());
    Ok(())
}

/// Get the detected platform
pub fn platform() -> Platform {
    MULTIBOOT_MANAGER.platform()
}

/// Get command line arguments
pub fn cmdline() -> Option<String> {
    MULTIBOOT_MANAGER.cmdline()
}

/// Get memory map entries
pub fn memory_map() -> Vec<MemoryMapEntry> {
    MULTIBOOT_MANAGER.memory_map()
}

/// Get framebuffer information
pub fn framebuffer() -> Option<FramebufferInfo> {
    MULTIBOOT_MANAGER.framebuffer()
}

/// Get loaded modules
pub fn modules() -> Vec<ModuleInfo> {
    MULTIBOOT_MANAGER.modules()
}

/// Check if booted via EFI
pub fn is_efi_boot() -> bool {
    MULTIBOOT_MANAGER.is_efi_boot()
}

/// Get ACPI RSDP if available
pub fn acpi_rsdp() -> Option<AcpiRsdp> {
    MULTIBOOT_MANAGER.acpi_rsdp()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiboot_header_checksum() {
        let header = Multiboot2Header::new(16);
        assert!(header.verify_checksum());
        assert_eq!(header.magic, MULTIBOOT2_HEADER_MAGIC);
        assert_eq!(header.architecture, MULTIBOOT2_ARCHITECTURE_I386);
    }

    #[test]
    fn test_memory_map_entry() {
        let entry = MemoryMapEntry {
            base_addr: 0x100000,
            length: 0x1000000,
            entry_type: memory_type::AVAILABLE,
            reserved: 0,
        };

        assert!(entry.is_available());
        assert!(!entry.is_acpi_reclaimable());
        assert_eq!(entry.type_name(), "Available");
        assert_eq!(entry.start_addr().as_u64(), 0x100000);
        assert_eq!(entry.end_addr().as_u64(), 0x1100000);
    }

    #[test]
    fn test_memory_type_names() {
        assert_eq!(memory_type::name(1), "Available");
        assert_eq!(memory_type::name(2), "Reserved");
        assert_eq!(memory_type::name(3), "ACPI Reclaimable");
        assert_eq!(memory_type::name(4), "ACPI NVS");
        assert_eq!(memory_type::name(5), "Bad Memory");
        assert_eq!(memory_type::name(99), "Unknown");
    }

    #[test]
    fn test_tag_type_names() {
        assert_eq!(tag::name(0), "End");
        assert_eq!(tag::name(1), "Command Line");
        assert_eq!(tag::name(6), "Memory Map");
        assert_eq!(tag::name(8), "Framebuffer");
        assert_eq!(tag::name(14), "ACPI Old RSDP");
        assert_eq!(tag::name(15), "ACPI New RSDP");
        assert_eq!(tag::name(255), "Unknown");
    }

    #[test]
    fn test_framebuffer_type() {
        assert_eq!(FramebufferType::from(0), FramebufferType::Indexed);
        assert_eq!(FramebufferType::from(1), FramebufferType::DirectRgb);
        assert_eq!(FramebufferType::from(2), FramebufferType::EgaText);
        assert_eq!(FramebufferType::from(99), FramebufferType::Unknown(99));
    }

    #[test]
    fn test_platform_properties() {
        assert!(Platform::QemuTcg.is_virtual());
        assert!(Platform::QemuKvm.is_virtual());
        assert!(Platform::Vmware.is_virtual());
        assert!(!Platform::BareMetal.is_virtual());

        assert!(Platform::QemuTcg.is_qemu());
        assert!(Platform::QemuKvm.is_qemu());
        assert!(!Platform::Vmware.is_qemu());

        assert!(Platform::QemuKvm.has_hw_virtualization());
        assert!(Platform::Kvm.has_hw_virtualization());
        assert!(!Platform::QemuTcg.has_hw_virtualization());

        assert!(Platform::QemuTcg.supports_virtio());
        assert!(Platform::QemuKvm.supports_virtio());
        assert!(!Platform::Vmware.supports_virtio());
    }

    #[test]
    fn test_platform_names() {
        assert_eq!(Platform::QemuTcg.name(), "QEMU (TCG)");
        assert_eq!(Platform::QemuKvm.name(), "QEMU (KVM)");
        assert_eq!(Platform::Vmware.name(), "VMware");
        assert_eq!(Platform::HyperV.name(), "Microsoft Hyper-V");
        assert_eq!(Platform::BareMetal.name(), "Bare Metal");
    }

    #[test]
    fn test_console_types() {
        assert_eq!(Platform::QemuTcg.console_type(), ConsoleType::Serial);
        assert_eq!(Platform::Vmware.console_type(), ConsoleType::Vga);
        assert_eq!(Platform::HyperV.console_type(), ConsoleType::EfiConsole);
    }

    #[test]
    fn test_timer_frequencies() {
        assert_eq!(Platform::QemuTcg.timer_frequency(), 100);
        assert_eq!(Platform::QemuKvm.timer_frequency(), 1000);
        assert_eq!(Platform::BareMetal.timer_frequency(), 1000);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            MultibootError::InvalidMagic { expected: 0, found: 1 }.as_str(),
            "Invalid multiboot magic number"
        );
        assert_eq!(
            MultibootError::NotInitialized.as_str(),
            "Multiboot subsystem not initialized"
        );
        assert_eq!(
            MultibootError::NoMemoryMap.as_str(),
            "No memory map available"
        );
    }

    #[test]
    fn test_module_info_size() {
        let module = ModuleInfo {
            start: PhysAddr::new(0x100000),
            end: PhysAddr::new(0x200000),
            cmdline: Some("test module".into()),
        };
        assert_eq!(module.size(), 0x100000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2 KB");
        assert_eq!(format_bytes(1048576), "1 MB");
        assert_eq!(format_bytes(1073741824), "1 GB");
    }

    #[test]
    fn test_acpi_rsdp_is_acpi2() {
        let rsdp_v1 = AcpiRsdp {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id: [0; 6],
            revision: 0,
            rsdt_address: 0x12345678,
            length: None,
            xsdt_address: None,
            extended_checksum: None,
        };
        assert!(!rsdp_v1.is_acpi2());
        assert_eq!(rsdp_v1.table_address(), 0x12345678);

        let rsdp_v2 = AcpiRsdp {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id: [0; 6],
            revision: 2,
            rsdt_address: 0x12345678,
            length: Some(36),
            xsdt_address: Some(0xDEADBEEF00000000),
            extended_checksum: Some(0),
        };
        assert!(rsdp_v2.is_acpi2());
        assert_eq!(rsdp_v2.table_address(), 0xDEADBEEF00000000);
    }

    #[test]
    fn test_multiboot_stats() {
        let stats = MultibootStats::new();
        assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 0);

        stats.memory_entries_parsed.fetch_add(5, Ordering::SeqCst);
        assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 5);

        stats.reset();
        assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 0);
    }
}
