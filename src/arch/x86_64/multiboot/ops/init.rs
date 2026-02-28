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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use x86_64::VirtAddr;

use super::super::error::MultibootError;
use super::super::framebuffer::FramebufferInfo;
use super::super::memory_map::MemoryMapEntry;
use super::super::modules::{AcpiRsdp, ModuleInfo};
use super::super::platform::{detect_platform, Platform};
use super::super::state::MULTIBOOT_MANAGER;
use super::platform_features::init_platform_features;

/// # Safety
/// Must be called early in boot with valid multiboot2 magic and info address.
pub unsafe fn init_with_info(magic: u32, info_addr: VirtAddr) -> Result<(), MultibootError> {
    unsafe {
        MULTIBOOT_MANAGER.initialize(magic, info_addr)?;

        let platform = MULTIBOOT_MANAGER.platform();
        init_platform_features(platform)?;

        Ok(())
    }
}

pub fn init() -> Result<(), MultibootError> {
    if MULTIBOOT_MANAGER.is_initialized() {
        return Ok(());
    }

    let platform = detect_platform();
    MULTIBOOT_MANAGER.set_platform(platform);

    crate::log::info!("Multiboot subsystem ready (platform: {})", platform.name());
    Ok(())
}

pub fn platform() -> Platform {
    MULTIBOOT_MANAGER.platform()
}

pub fn cmdline() -> Option<String> {
    MULTIBOOT_MANAGER.cmdline()
}

pub fn memory_map() -> Vec<MemoryMapEntry> {
    MULTIBOOT_MANAGER.memory_map()
}

pub fn framebuffer() -> Option<FramebufferInfo> {
    MULTIBOOT_MANAGER.framebuffer()
}

pub fn modules() -> Vec<ModuleInfo> {
    MULTIBOOT_MANAGER.modules()
}

pub fn is_efi_boot() -> bool {
    MULTIBOOT_MANAGER.is_efi_boot()
}

pub fn acpi_rsdp() -> Option<AcpiRsdp> {
    MULTIBOOT_MANAGER.acpi_rsdp()
}
