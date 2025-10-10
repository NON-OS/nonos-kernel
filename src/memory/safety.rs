//! Memory Safety Validation Module
//!
//! Provides production-ready memory safety checks and validation functions
//! to prevent memory corruption and improve system stability.

use crate::log::logger::log_critical;
use crate::memory::layout::{KERNEL_BASE, PAGE_SIZE};
use alloc::format;
use core::ptr;

/// Memory region bounds
pub struct MemoryBounds {
    pub start: u64,
    pub end: u64,
    pub name: &'static str,
}

/// Common memory regions for validation
pub const KERNEL_TEXT: MemoryBounds = MemoryBounds {
    start: KERNEL_BASE,
    end: KERNEL_BASE + 0x400000, // 4MB kernel text region
    name: "Kernel Text",
};

pub const KERNEL_HEAP: MemoryBounds = MemoryBounds {
    start: crate::memory::heap::HEAP_START as u64,
    end: (crate::memory::heap::HEAP_START + crate::memory::heap::HEAP_SIZE) as u64,
    name: "Kernel Heap",
};

pub const VGA_BUFFER: MemoryBounds =
    MemoryBounds { start: 0xB8000, end: 0xB8FA0, name: "VGA Buffer" };

/// Validate that a memory address is within expected bounds
pub fn validate_address_bounds(addr: u64, size: usize, bounds: &MemoryBounds) -> bool {
    let end_addr = addr.saturating_add(size as u64);

    if addr < bounds.start || end_addr > bounds.end {
        log_critical(&format!(
            "Memory bounds violation: addr=0x{:x}, size=0x{:x}, region={} [0x{:x}-0x{:x}]",
            addr, size, bounds.name, bounds.start, bounds.end
        ));
        return false;
    }

    true
}

/// Validate pointer alignment and bounds
pub fn validate_pointer_safety<T>(ptr: *const T, bounds: &MemoryBounds) -> bool {
    if ptr.is_null() {
        log_critical("Null pointer validation failed");
        return false;
    }

    let addr = ptr as u64;
    let size = core::mem::size_of::<T>();
    let alignment = core::mem::align_of::<T>();

    // Check alignment
    if addr % (alignment as u64) != 0 {
        log_critical(&format!(
            "Pointer alignment violation: addr=0x{:x}, required_align={}",
            addr, alignment
        ));
        return false;
    }

    // Check bounds
    if !validate_address_bounds(addr, size, bounds) {
        return false;
    }

    true
}

/// Safe memory copy with bounds checking
pub unsafe fn safe_copy_memory(
    dest: *mut u8,
    src: *const u8,
    count: usize,
    dest_bounds: &MemoryBounds,
    src_bounds: &MemoryBounds,
) -> Result<(), &'static str> {
    // Validate source
    if !validate_address_bounds(src as u64, count, src_bounds) {
        return Err("Source bounds violation");
    }

    // Validate destination
    if !validate_address_bounds(dest as u64, count, dest_bounds) {
        return Err("Destination bounds violation");
    }

    // Check for overlap
    let src_start = src as usize;
    let src_end = src_start + count;
    let dest_start = dest as usize;
    let dest_end = dest_start + count;

    if src_start < dest_end && dest_start < src_end {
        return Err("Memory regions overlap");
    }

    // Perform the copy
    ptr::copy_nonoverlapping(src, dest, count);
    Ok(())
}

/// Validate that a memory region is properly page-aligned
pub fn validate_page_alignment(addr: u64, size: usize) -> bool {
    if addr % (PAGE_SIZE as u64) != 0 {
        log_critical(&format!(
            "Page alignment violation: addr=0x{:x} not aligned to page size {}",
            addr, PAGE_SIZE
        ));
        return false;
    }

    if size % PAGE_SIZE != 0 {
        log_critical(&format!(
            "Page size violation: size=0x{:x} not multiple of page size {}",
            size, PAGE_SIZE
        ));
        return false;
    }

    true
}

/// Check if address is in kernel space
pub fn is_kernel_address(addr: u64) -> bool {
    addr >= KERNEL_BASE
}

/// Check if address is in user space
pub fn is_user_address(addr: u64) -> bool {
    addr < 0x0000_8000_0000_0000
}

/// Validate virtual address is canonical on x86_64
pub fn is_canonical_address(addr: u64) -> bool {
    // On x86_64, canonical addresses have bits 63:48 either all 0 or all 1
    let high_bits = addr >> 48;
    high_bits == 0 || high_bits == 0xFFFF
}

/// Comprehensive address validation
pub fn validate_virtual_address(addr: u64, size: usize, kernel_only: bool) -> bool {
    // Check canonical form
    if !is_canonical_address(addr) {
        log_critical(&format!("Non-canonical address: 0x{:x}", addr));
        return false;
    }

    // Check end address is also canonical
    let end_addr = addr.saturating_add(size as u64);
    if !is_canonical_address(end_addr) {
        log_critical(&format!("Non-canonical end address: 0x{:x}", end_addr));
        return false;
    }

    // Check privilege level if required
    if kernel_only && !is_kernel_address(addr) {
        log_critical(&format!("User address in kernel-only context: 0x{:x}", addr));
        return false;
    }

    true
}

/// Memory guard pattern for detecting corruption
pub const GUARD_PATTERN: u64 = 0xDEADBEEFCAFEBABE;

/// Write guard pattern to memory location
pub unsafe fn write_guard_pattern(ptr: *mut u64) {
    if !ptr.is_null() {
        ptr.write_volatile(GUARD_PATTERN);
    }
}

/// Check guard pattern and return true if intact
pub unsafe fn check_guard_pattern(ptr: *const u64) -> bool {
    if ptr.is_null() {
        return false;
    }

    let value = ptr.read_volatile();
    if value != GUARD_PATTERN {
        log_critical(&format!(
            "Guard pattern corruption detected at 0x{:p}: expected 0x{:x}, found 0x{:x}",
            ptr, GUARD_PATTERN, value
        ));
        return false;
    }

    true
}
