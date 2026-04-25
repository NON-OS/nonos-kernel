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

pub const ARCH_SET_GS: i32 = 0x1001;
pub const ARCH_SET_FS: i32 = 0x1002;
pub const ARCH_GET_FS: i32 = 0x1003;
pub const ARCH_GET_GS: i32 = 0x1004;
pub const ARCH_GET_CPUID: i32 = 0x1011;
pub const ARCH_SET_CPUID: i32 = 0x1012;
pub const ARCH_MAP_VDSO_X32: i32 = 0x2001;
pub const ARCH_MAP_VDSO_32: i32 = 0x2002;
pub const ARCH_MAP_VDSO_64: i32 = 0x2003;

pub const GDT_ENTRY_TLS_MIN: usize = 6;
pub const GDT_ENTRY_TLS_MAX: usize = 8;
pub const GDT_ENTRY_TLS_ENTRIES: usize = 3;
pub const GDT_ENTRIES: usize = 16;

pub const DESC_FLAG_SEG_32BIT: u32 = 1 << 0;
pub const DESC_FLAG_CONTENTS_MASK: u32 = 3 << 1;
pub const DESC_FLAG_READ_EXEC_ONLY: u32 = 1 << 3;
pub const DESC_FLAG_LIMIT_IN_PAGES: u32 = 1 << 4;
pub const DESC_FLAG_SEG_NOT_PRESENT: u32 = 1 << 5;
pub const DESC_FLAG_USEABLE: u32 = 1 << 6;
pub const DESC_FLAG_LM: u32 = 1 << 7;

pub const MSR_FS_BASE: u32 = 0xC0000100;
pub const MSR_GS_BASE: u32 = 0xC0000101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GdtEntry64 {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TlsDescriptor {
    pub base: u64,
    pub limit: u32,
    pub flags: u32,
    pub selector: u16,
    pub valid: bool,
}

impl UserDesc {
    pub fn seg_32bit(&self) -> bool {
        self.flags & DESC_FLAG_SEG_32BIT != 0
    }
    pub fn contents(&self) -> u32 {
        (self.flags & DESC_FLAG_CONTENTS_MASK) >> 1
    }
    pub fn read_exec_only(&self) -> bool {
        self.flags & DESC_FLAG_READ_EXEC_ONLY != 0
    }
    pub fn limit_in_pages(&self) -> bool {
        self.flags & DESC_FLAG_LIMIT_IN_PAGES != 0
    }
    pub fn seg_not_present(&self) -> bool {
        self.flags & DESC_FLAG_SEG_NOT_PRESENT != 0
    }
    pub fn useable(&self) -> bool {
        self.flags & DESC_FLAG_USEABLE != 0
    }
    pub fn lm(&self) -> bool {
        self.flags & DESC_FLAG_LM != 0
    }

    pub fn to_gdt_entry(&self) -> GdtEntry64 {
        let mut entry = GdtEntry64::default();
        entry.limit_low = (self.limit & 0xFFFF) as u16;
        entry.base_low = (self.base_addr & 0xFFFF) as u16;
        entry.base_mid = ((self.base_addr >> 16) & 0xFF) as u8;
        entry.access = 0xF2 | if self.read_exec_only() { 0 } else { 2 };
        entry.granularity = ((self.limit >> 16) & 0x0F) as u8;
        if self.limit_in_pages() {
            entry.granularity |= 0x80;
        }
        if self.seg_32bit() {
            entry.granularity |= 0x40;
        }
        entry.base_high = ((self.base_addr >> 24) & 0xFF) as u8;
        entry
    }
}
