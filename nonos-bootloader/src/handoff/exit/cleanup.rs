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

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

pub fn secure_cleanup_before_jump() {
    wipe_crypto_state();
    wipe_zk_state();
    wipe_signing_keys();
    wipe_entropy_pools();
    flush_cpu_state();
    compiler_fence(Ordering::SeqCst);
}

fn wipe_crypto_state() {
    crate::crypto::keystore_v2::wipe_all_keys();
}

fn wipe_zk_state() {
    crate::zk::transcript::wipe_transcript();
}

fn wipe_signing_keys() {
    crate::crypto::sig::wipe_signing_state();
}

fn wipe_entropy_pools() {
    crate::entropy::wipe_entropy_state();
}

fn flush_cpu_state() {
    unsafe {
        core::arch::asm!(
            "xor rax, rax",
            "xor rbx, rbx",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r11, r11",
            "xor r12, r12",
            "xor r13, r13",
            "xor r14, r14",
            "xor r15, r15",
            options(nomem, nostack)
        );
    }
}

#[inline(never)]
pub fn secure_wipe_region(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 { return; }
    for i in 0..len {
        unsafe { ptr::write_volatile(ptr.add(i), 0x00); }
    }
    compiler_fence(Ordering::SeqCst);
    for i in 0..len {
        unsafe { ptr::write_volatile(ptr.add(i), 0xFF); }
    }
    compiler_fence(Ordering::SeqCst);
    for i in 0..len {
        unsafe { ptr::write_volatile(ptr.add(i), 0x00); }
    }
    compiler_fence(Ordering::SeqCst);
}
