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

//! MMIO Read/Write Operations
//!
//! Volatile memory-mapped I/O access with proper barriers.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use x86_64::VirtAddr;

use super::stats::MMIO_STATS;

// ============================================================================
// VALIDATED READ OPERATIONS
// ============================================================================

/// Reads an 8-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and properly aligned.
#[inline]
pub(super) unsafe fn read8_at(addr: u64) -> u8 { unsafe {
    let ptr = addr as *const u8;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_read();
    value
}}

/// Reads a 16-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 2-byte aligned.
#[inline]
pub(super) unsafe fn read16_at(addr: u64) -> u16 { unsafe {
    let ptr = addr as *const u16;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_read();
    value
}}

/// Reads a 32-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 4-byte aligned.
#[inline]
pub(super) unsafe fn read32_at(addr: u64) -> u32 { unsafe {
    let ptr = addr as *const u32;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_read();
    value
}}

/// Reads a 64-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 8-byte aligned.
#[inline]
pub(super) unsafe fn read64_at(addr: u64) -> u64 { unsafe {
    let ptr = addr as *const u64;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_read();
    value
}}

// ============================================================================
// VALIDATED WRITE OPERATIONS
// ============================================================================

/// Writes an 8-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address.
#[inline]
pub(super) unsafe fn write8_at(addr: u64, value: u8) { unsafe {
    let ptr = addr as *mut u8;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_write();
}}

/// Writes a 16-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 2-byte aligned.
#[inline]
pub(super) unsafe fn write16_at(addr: u64, value: u16) { unsafe {
    let ptr = addr as *mut u16;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_write();
}}

/// Writes a 32-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 4-byte aligned.
#[inline]
pub(super) unsafe fn write32_at(addr: u64, value: u32) { unsafe {
    let ptr = addr as *mut u32;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_write();
}}

/// Writes a 64-bit value with validation.
///
/// # Safety
///
/// The address must be a valid MMIO address and 8-byte aligned.
#[inline]
pub(super) unsafe fn write64_at(addr: u64, value: u64) { unsafe {
    let ptr = addr as *mut u64;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    MMIO_STATS.record_write();
}}

// ============================================================================
// DIRECT ACCESS (NO VALIDATION)
// ============================================================================

/// Reads 8 bits from a VirtAddr directly.
#[inline]
pub fn mmio_r8(va: VirtAddr) -> u8 {
    MMIO_STATS.record_read();
    // SAFETY: Caller ensures address is valid MMIO
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

/// Reads 16 bits from a VirtAddr directly.
#[inline]
pub fn mmio_r16(va: VirtAddr) -> u16 {
    MMIO_STATS.record_read();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

/// Reads 32 bits from a VirtAddr directly.
#[inline]
pub fn mmio_r32(va: VirtAddr) -> u32 {
    MMIO_STATS.record_read();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

/// Reads 64 bits from a VirtAddr directly.
#[inline]
pub fn mmio_r64(va: VirtAddr) -> u64 {
    MMIO_STATS.record_read();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

/// Writes 8 bits to a VirtAddr directly.
#[inline]
pub fn mmio_w8(va: VirtAddr, value: u8) {
    MMIO_STATS.record_write();
    // SAFETY: Caller ensures address is valid MMIO
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

/// Writes 16 bits to a VirtAddr directly.
#[inline]
pub fn mmio_w16(va: VirtAddr, value: u16) {
    MMIO_STATS.record_write();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

/// Writes 32 bits to a VirtAddr directly.
#[inline]
pub fn mmio_w32(va: VirtAddr, value: u32) {
    MMIO_STATS.record_write();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

/// Writes 64 bits to a VirtAddr directly.
#[inline]
pub fn mmio_w64(va: VirtAddr, value: u64) {
    MMIO_STATS.record_write();
    // SAFETY: Caller ensures address is valid MMIO and aligned
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}
