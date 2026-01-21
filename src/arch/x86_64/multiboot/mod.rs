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

pub mod constants;
pub mod error;
pub mod framebuffer;
pub mod header;
pub mod info;
pub mod memory_map;
pub mod modules;
mod ops;
pub mod platform;
pub mod state;
pub mod stats;

#[cfg(test)]
mod tests;

pub use constants::{
    memory_type, tag, MULTIBOOT2_ARCHITECTURE_I386, MULTIBOOT2_BOOTLOADER_MAGIC,
    MULTIBOOT2_HEADER_MAGIC,
};
pub use error::MultibootError;
pub use framebuffer::{ColorInfo, FramebufferInfo, FramebufferType};
pub use header::{Multiboot2Header, Multiboot2Info, TagHeader};
pub use info::ParsedMultibootInfo;
pub use memory_map::{EfiMemoryDescriptor, MemoryMapEntry};
pub use modules::{
    AcpiRsdp, ApmTable, BasicMemInfo, BiosBootDevice, ElfSection, ElfSections, ModuleInfo,
    SmbiosInfo, VbeInfo,
};
pub use ops::{
    acpi_rsdp, cmdline, framebuffer, get_fallback_memory_regions, get_safe_memory_regions, init,
    init_platform_features, init_with_info, is_efi_boot, memory_map, modules, platform,
};
pub use platform::{detect_platform, ConsoleType, Platform};
pub use state::{MultibootManager, MULTIBOOT_MANAGER};
pub use stats::MultibootStats;
