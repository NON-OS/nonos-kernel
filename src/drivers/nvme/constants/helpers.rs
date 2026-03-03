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

use super::registers::*;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;
pub const PAGE_SHIFT: u32 = 12;

pub const ADMIN_QUEUE_DEPTH: u16 = 32;
pub const IO_QUEUE_DEPTH: u16 = 256;
pub const MAX_IO_QUEUES: u16 = 64;

pub const SUBMISSION_ENTRY_SIZE: usize = 64;
pub const COMPLETION_ENTRY_SIZE: usize = 16;

pub const DEFAULT_TIMEOUT_SPINS: u32 = 2_000_000;
pub const ENABLE_TIMEOUT_SPINS: u32 = 5_000_000;
pub const DISABLE_TIMEOUT_SPINS: u32 = 5_000_000;

pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 100_000;
pub const RATE_WINDOW_MS: u64 = 1000;

pub const KERNEL_PHYS_START: u64 = 0x0000_0000_0000_0000;
pub const KERNEL_PHYS_END: u64 = 0x0000_0000_4000_0000;
pub const MAX_DMA_SIZE: usize = 128 * 1024 * 1024;
pub const MAX_TRANSFER_SIZE: usize = 2 * 1024 * 1024;

pub const MAX_PRP_ENTRIES_PER_PAGE: usize = PAGE_SIZE / 8;

pub const MAX_CID_MISMATCHES: u32 = 10;

#[inline]
pub const fn doorbell_sq_offset(dstrd: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize) * (4 << dstrd)
}

#[inline]
pub const fn doorbell_cq_offset(dstrd: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize + 1) * (4 << dstrd)
}

#[inline]
pub const fn cap_mqes(cap: u64) -> u16 {
    (cap & CAP_MQES_MASK) as u16
}

#[inline]
pub const fn cap_timeout_ms(cap: u64) -> u32 {
    let to = ((cap & CAP_TO_MASK) >> CAP_TO_SHIFT) as u32;
    to * 500
}

#[inline]
pub const fn cap_dstrd(cap: u64) -> u32 {
    ((cap & CAP_DSTRD_MASK) >> CAP_DSTRD_SHIFT) as u32
}

#[inline]
pub const fn cap_mpsmin(cap: u64) -> u32 {
    ((cap & CAP_MPSMIN_MASK) >> CAP_MPSMIN_SHIFT) as u32
}

#[inline]
pub const fn cap_mpsmax(cap: u64) -> u32 {
    ((cap & CAP_MPSMAX_MASK) >> CAP_MPSMAX_SHIFT) as u32
}

#[inline]
pub const fn cc_mps(page_shift: u32) -> u32 {
    ((page_shift - 12) & 0xF) << CC_MPS_SHIFT
}

#[inline]
pub const fn cc_sqes(entry_size_log2: u32) -> u32 {
    (entry_size_log2 & 0xF) << CC_IOSQES_SHIFT
}

#[inline]
pub const fn cc_cqes(entry_size_log2: u32) -> u32 {
    (entry_size_log2 & 0xF) << CC_IOCQES_SHIFT
}

#[inline]
pub const fn aqa(asqs: u16, acqs: u16) -> u32 {
    ((asqs.saturating_sub(1) as u32) & 0xFFF) | (((acqs.saturating_sub(1) as u32) & 0xFFF) << 16)
}

#[inline]
pub const fn version_major(vs: u32) -> u16 {
    ((vs >> 16) & 0xFFFF) as u16
}

#[inline]
pub const fn version_minor(vs: u32) -> u8 {
    ((vs >> 8) & 0xFF) as u8
}

#[inline]
pub const fn version_tertiary(vs: u32) -> u8 {
    (vs & 0xFF) as u8
}
