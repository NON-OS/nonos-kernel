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
//! NØNOS x86_64 Multiboot2 Module
//! This module provides Multiboot2 boot protocol support for QEMU, VMs, and bare-metal.

pub mod nonos_multiboot;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_multiboot::MultibootError;

// ============================================================================
// Constants
// ============================================================================

pub use nonos_multiboot::MULTIBOOT2_HEADER_MAGIC;
pub use nonos_multiboot::MULTIBOOT2_BOOTLOADER_MAGIC;
pub use nonos_multiboot::MULTIBOOT2_ARCHITECTURE_I386;
pub use nonos_multiboot::tag;
pub use nonos_multiboot::memory_type;

// ============================================================================
// Core Structures
// ============================================================================

pub use nonos_multiboot::Multiboot2Header;
pub use nonos_multiboot::Multiboot2Info;
pub use nonos_multiboot::TagHeader;
pub use nonos_multiboot::MemoryMapEntry;
pub use nonos_multiboot::FramebufferInfo;
pub use nonos_multiboot::FramebufferType;
pub use nonos_multiboot::ColorInfo;
pub use nonos_multiboot::ModuleInfo;
pub use nonos_multiboot::BasicMemInfo;
pub use nonos_multiboot::BiosBootDevice;
pub use nonos_multiboot::VbeInfo;
pub use nonos_multiboot::ElfSections;
pub use nonos_multiboot::ElfSection;
pub use nonos_multiboot::ApmTable;
pub use nonos_multiboot::AcpiRsdp;
pub use nonos_multiboot::SmbiosInfo;
pub use nonos_multiboot::EfiMemoryDescriptor;
pub use nonos_multiboot::ParsedMultibootInfo;

// ============================================================================
// Platform Types
// ============================================================================

pub use nonos_multiboot::Platform;
pub use nonos_multiboot::ConsoleType;

// ============================================================================
// Statistics
// ============================================================================

pub use nonos_multiboot::MultibootStats;

// ============================================================================
// Manager
// ============================================================================

pub use nonos_multiboot::MultibootManager;
pub use nonos_multiboot::MULTIBOOT_MANAGER;

// ============================================================================
// Public API
// ============================================================================

/// Initialize multiboot subsystem (basic)
#[inline]
pub fn init() -> Result<(), MultibootError> {
    nonos_multiboot::init()
}

/// Initialize with multiboot2 info
///
/// # Safety
/// The info_addr must point to a valid Multiboot2 information structure.
#[inline]
pub unsafe fn init_with_info(
    magic: u32,
    info_addr: x86_64::VirtAddr,
) -> Result<(), MultibootError> {
    nonos_multiboot::init_with_info(magic, info_addr)
}

/// Detect platform (QEMU, KVM, VMware, etc.)
#[inline]
pub fn detect_platform() -> Platform {
    nonos_multiboot::detect_platform()
}

/// Get current platform
#[inline]
pub fn platform() -> Platform {
    nonos_multiboot::platform()
}

/// Initialize platform-specific features
#[inline]
pub fn init_platform_features(platform: Platform) -> Result<(), MultibootError> {
    nonos_multiboot::init_platform_features(platform)
}

/// Get command line
#[inline]
pub fn cmdline() -> Option<alloc::string::String> {
    nonos_multiboot::cmdline()
}

/// Get memory map entries
#[inline]
pub fn memory_map() -> alloc::vec::Vec<MemoryMapEntry> {
    nonos_multiboot::memory_map()
}

/// Get framebuffer info
#[inline]
pub fn framebuffer() -> Option<FramebufferInfo> {
    nonos_multiboot::framebuffer()
}

/// Get loaded modules
#[inline]
pub fn modules() -> alloc::vec::Vec<ModuleInfo> {
    nonos_multiboot::modules()
}

/// Check if booted via EFI
#[inline]
pub fn is_efi_boot() -> bool {
    nonos_multiboot::is_efi_boot()
}

/// Get ACPI RSDP if available
#[inline]
pub fn acpi_rsdp() -> Option<AcpiRsdp> {
    nonos_multiboot::acpi_rsdp()
}

/// Get safe memory regions
#[inline]
pub fn get_safe_memory_regions() -> Result<alloc::vec::Vec<crate::memory::layout::Region>, MultibootError> {
    nonos_multiboot::get_safe_memory_regions()
}

/// Get fallback memory regions
#[inline]
pub fn get_fallback_memory_regions(platform: Platform) -> alloc::vec::Vec<crate::memory::layout::Region> {
    nonos_multiboot::get_fallback_memory_regions(platform)
}
