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

use alloc::vec::Vec;
use x86_64::PhysAddr;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultibootError {
    InvalidSize,
    InvalidTag { tag_type: u32 },
    MemoryMapError,
    FramebufferError,
    ModuleError,
    InvalidCmdline,
}

impl MultibootError {
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

#[repr(C, align(8))]
pub struct Multiboot2Header {
    /// Magic number (0xE85250D6)
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
}

#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

pub mod memory_type {
    pub const AVAILABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;
}

impl MemoryMapEntry {
    #[inline]
    pub fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    #[inline]
    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    #[inline]
    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    #[inline]
    pub fn size(&self) -> u64 {
        self.length
    }

    #[inline]
    pub fn page_count(&self) -> u64 {
        self.length / 4096
    }
}

#[derive(Debug, Clone)]
pub struct MultibootInfo {
    pub memory_map: Vec<MemoryMapEntry>,
    pub framebuffer_info: Option<FramebufferInfo>,
    pub module_info: Option<ModuleInfo>,
}

impl MultibootInfo {
    pub fn total_available_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.length)
            .sum()
    }

    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryMapEntry> {
        self.memory_map
            .iter()
            .filter(|e| e.is_available() && e.base_addr >= 0x100000)
    }

    #[inline]
    pub fn has_framebuffer(&self) -> bool {
        self.framebuffer_info.is_some()
    }

    #[inline]
    pub fn has_module(&self) -> bool {
        self.module_info.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub framebuffer_type: u8,
}

impl FramebufferInfo {
    #[inline]
    pub fn size(&self) -> usize {
        (self.pitch as usize) * (self.height as usize)
    }

    #[inline]
    pub fn is_rgb(&self) -> bool {
        self.framebuffer_type == 1
    }

    #[inline]
    pub fn is_text_mode(&self) -> bool {
        self.framebuffer_type == 2
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub cmdline: Option<&'static str>,
}

impl ModuleInfo {
    #[inline]
    pub fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

/// /// /// /// TESTS /// /// /// /// 
#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use super::*;

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
    fn test_error_display() {
        let e = MultibootError::InvalidSize;
        assert_eq!(e.as_str(), "Invalid multiboot info size");

        let e = MultibootError::InvalidTag { tag_type: 99 };
        let s = alloc::format!("{}", e);
        assert!(s.contains("99"));
    }
}
