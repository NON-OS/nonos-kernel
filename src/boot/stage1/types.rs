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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub ty: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

/// EFI memory type for conventional (usable) memory
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
#[repr(C)]
pub struct BootInfo {
    pub memory_map: &'static [MemoryDescriptor],
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp_addr: Option<u64>,
    pub kernel_image_offset: u64,
}

#[repr(C)]
pub struct FramebufferInfo {
    pub buffer_addr: u64,
    pub buffer_size: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}
