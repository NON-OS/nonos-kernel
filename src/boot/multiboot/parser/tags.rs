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

pub mod tag_type {
    pub const END: u32 = 0;
    pub const MODULE: u32 = 3;
    pub const MMAP: u32 = 6;
    pub const FRAMEBUFFER: u32 = 8;
}

#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}

#[repr(C)]
pub struct MemoryMapTag {
    pub tag_type: u32,
    pub size: u32,
    pub entry_size: u32,
    pub entry_version: u32,
}

#[repr(C)]
pub struct FramebufferTag {
    pub tag_type: u32,
    pub size: u32,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
    pub reserved: u8,
}

#[repr(C)]
pub struct ModuleTag {
    pub tag_type: u32,
    pub size: u32,
    pub mod_start: u32,
    pub mod_end: u32,
}
