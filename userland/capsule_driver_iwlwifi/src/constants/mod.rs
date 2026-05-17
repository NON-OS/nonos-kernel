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

pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const BAR_INDEX: u32 = 0;
pub const BAR_OFFSET: u64 = 0;
pub const FW_STAGING_SIZE: u64 = 64 * 1024;
pub const PAGE_MASK: u64 = 0xFFF;
pub const CSR_INT_COALESCING: usize = 0x004;
pub const CSR_INT: usize = 0x008;
pub const CSR_INT_MASK: usize = 0x00C;
pub const CSR_FH_INT_STATUS: usize = 0x010;
pub const CSR_GP_CNTRL: usize = 0x024;
pub const CSR_HW_REV: usize = 0x028;
pub const GP_CNTRL_MAC_CLOCK_READY: u32 = 0x0000_0002;
pub const GP_CNTRL_INIT_DONE: u32 = 0x0000_0004;
pub const GP_CNTRL_MAC_ACCESS_REQ: u32 = 0x0000_0008;
pub const GP_CNTRL_XTAL_ON: u32 = 0x0000_0400;
pub const ALL_INTS_MASK: u32 = 0xFFFF_FFFF;
pub const INT_MASK_DISABLED: u32 = 0;
pub const INT_COALESCING_TIMEOUT: u32 = 64;
pub const APM_POLL_ITERS: usize = 250_000;
pub const INT_BIT_ALIVE: u32 = 1 << 0;
pub const ALIVE_POLL_ITERS: usize = 2_000_000;
pub const IWL_FW_MAGIC: u32 = 0x0A4C_5749;
pub const FW_API_VERSION_MASK: u32 = 0xFFFF;
pub const MIN_FW_API_VERSION: u16 = 22;
pub const MAX_FW_API_VERSION: u16 = 77;
