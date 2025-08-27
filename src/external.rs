// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.

//! NØNOS External Function Implementations
//!
//! Provides implementations for extern functions referenced throughout the kernel.

use core::sync::atomic::{AtomicU64, Ordering};

// Virtual memory allocator for kernel VM region
static KVM_CURSOR: AtomicU64 = AtomicU64::new(0xFFFF_8800_0000_0000);

#[no_mangle]
pub extern "Rust" fn __nonos_alloc_kvm_va(pages: usize) -> u64 {
    let size = (pages * 4096) as u64;
    let addr = KVM_CURSOR.fetch_add(size, Ordering::SeqCst);
    
    // Check bounds
    const KVM_END: u64 = 0xFFFF_8900_0000_0000;
    if addr + size > KVM_END {
        0 // Out of space
    } else {
        addr
    }
}

// MMIO allocator
static MMIO_CURSOR: AtomicU64 = AtomicU64::new(0xFFFF_C000_0000_0000);

#[no_mangle]
pub extern "Rust" fn __nonos_alloc_mmio_va(pages: usize) -> u64 {
    let size = (pages * 4096) as u64;
    let addr = MMIO_CURSOR.fetch_add(size, Ordering::SeqCst);
    
    const MMIO_END: u64 = 0xFFFF_C100_0000_0000;
    if addr + size > MMIO_END {
        0
    } else {
        addr
    }
}

// GUI bridge stubs (implementations would connect to actual device/transport)
#[no_mangle]
pub extern "C" fn __nonos_gui_write(ptr: *const u8, len: usize) -> isize {
    // In real implementation, this would write to a shared memory region
    // or serial port designated for GUI communication
    len as isize
}

#[no_mangle]
pub extern "C" fn __nonos_gui_read(ptr: *mut u8, len: usize) -> isize {
    // Would read from GUI input buffer
    0
}

// Timer helper
pub mod timer_helpers {
    #[no_mangle]
    pub unsafe extern "Rust" fn now_ns_checked() -> Option<u64> {
        // Check if timer is initialized
        if crate::arch::x86_64::time::timer::is_initialized() {
            Some(crate::arch::x86_64::time::timer::now_ns())
        } else {
            None
        }
    }
}
