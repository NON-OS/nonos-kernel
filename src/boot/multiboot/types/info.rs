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

use super::memory::MemoryMapEntry;

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
