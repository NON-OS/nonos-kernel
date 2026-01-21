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

pub const MAX_CPUS: usize = 256;
pub const TSS_SIZE: usize = 104;
pub const IST_COUNT: usize = 7;
pub const DEFAULT_STACK_SIZE: usize = 16384;
pub const IOPB_SIZE: usize = 8192;
// Segment selectors
pub const SEL_NULL: u16 = 0x00;
pub const SEL_KERNEL_CODE: u16 = 0x08;
pub const SEL_KERNEL_DATA: u16 = 0x10;
pub const SEL_USER_DATA: u16 = 0x18 | 3;
pub const SEL_USER_CODE: u16 = 0x20 | 3;
pub const SEL_TSS: u16 = 0x28;
pub const SEL_KERNEL_CODE_RAW: u16 = 0x08;
pub const SEL_KERNEL_DATA_RAW: u16 = 0x10;
pub const SEL_USER_DATA_RAW: u16 = 0x18;
pub const SEL_USER_CODE_RAW: u16 = 0x20;
// IST indices
pub const IST_DOUBLE_FAULT: usize = 1;
pub const IST_NMI: usize = 2;
pub const IST_MACHINE_CHECK: usize = 3;
pub const IST_DEBUG: usize = 4;
pub const IST_PAGE_FAULT: usize = 5;
pub const IST_GP: usize = 6;
// Access byte flags (internal)
pub(crate) const ACCESS_PRESENT: u8 = 1 << 7;
pub(crate) const ACCESS_DPL_RING0: u8 = 0 << 5;
pub(crate) const ACCESS_DPL_RING3: u8 = 3 << 5;
pub(crate) const ACCESS_TYPE_SYSTEM: u8 = 0 << 4;
pub(crate) const ACCESS_TYPE_CODE_DATA: u8 = 1 << 4;
pub(crate) const ACCESS_EXECUTABLE: u8 = 1 << 3;
pub(crate) const ACCESS_RW: u8 = 1 << 1;
// TSS types (internal)
pub(crate) const TSS_TYPE_AVAILABLE_64: u8 = 0x9;
pub(crate) const TSS_TYPE_BUSY_64: u8 = 0xB;
// Flags (internal)
pub(crate) const FLAG_GRANULARITY: u8 = 1 << 7;
pub(crate) const FLAG_SIZE_32: u8 = 1 << 6;
pub(crate) const FLAG_LONG_MODE: u8 = 1 << 5;
// MSR addresses
pub(crate) const MSR_FS_BASE: u32 = 0xC000_0100;
pub(crate) const MSR_GS_BASE: u32 = 0xC000_0101;
pub(crate) const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub(crate) const MSR_EFER: u32 = 0xC000_0080;
pub(crate) const MSR_STAR: u32 = 0xC000_0081;
pub(crate) const MSR_LSTAR: u32 = 0xC000_0082;
pub(crate) const MSR_SFMASK: u32 = 0xC000_0084;
pub(crate) const EFER_SCE: u64 = 1 << 0;

pub const DEFAULT_SYSCALL_MASK: u64 = (1 << 9) | (1 << 8) | (1 << 10) | (1 << 18) | (1 << 14);
