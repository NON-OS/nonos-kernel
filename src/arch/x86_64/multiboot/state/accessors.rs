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
use core::sync::atomic::Ordering;

use super::types::MultibootManager;
use super::super::framebuffer::FramebufferInfo;
use super::super::info::ParsedMultibootInfo;
use super::super::memory_map::MemoryMapEntry;
use super::super::modules::{AcpiRsdp, ModuleInfo};
use super::super::platform::Platform;
use super::super::stats::MultibootStats;

impl MultibootManager {
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn platform(&self) -> Platform {
        *self.platform.read()
    }

    pub fn set_platform(&self, platform: Platform) {
        *self.platform.write() = platform;
    }

    pub fn info(&self) -> Option<ParsedMultibootInfo> {
        self.parsed_info.read().clone()
    }

    pub fn stats(&self) -> &MultibootStats {
        &self.stats
    }

    pub fn cmdline(&self) -> Option<String> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.cmdline.clone())
    }

    pub fn bootloader_name(&self) -> Option<String> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.bootloader_name.clone())
    }

    pub fn memory_map(&self) -> Vec<MemoryMapEntry> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.memory_map.clone())
            .unwrap_or_default()
    }

    pub fn framebuffer(&self) -> Option<FramebufferInfo> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.framebuffer.clone())
    }

    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.modules.clone())
            .unwrap_or_default()
    }

    pub fn acpi_rsdp(&self) -> Option<AcpiRsdp> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.acpi_rsdp.clone())
    }

    pub fn is_efi_boot(&self) -> bool {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.is_efi_boot())
            .unwrap_or(false)
    }
}
