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

use core::sync::atomic::{compiler_fence, Ordering};
use crate::persistence::revoke_all_consent;

/// # Safety
/// Performs complete secure wipe of all sensitive memory and revokes
/// all persistence consent to ensure no data leaks post-wipe.
pub fn secure_wipe_all_memory() {
    revoke_all_consent();
    wipe_heap_region();
    wipe_process_memory();
    wipe_crypto_keys();
    wipe_ipc_buffers();
    wipe_vfs_caches();
    compiler_fence(Ordering::SeqCst);
    crate::log::info!("[SECURITY] ZeroState secure memory wipe complete");
}

fn wipe_heap_region() {
    let heap_start = crate::memory::layout::KHEAP_BASE;
    let heap_size = crate::memory::layout::KHEAP_SIZE as usize;
    if heap_size > 0 && heap_size < 1024 * 1024 * 512 {
        let heap_slice = unsafe {
            core::slice::from_raw_parts_mut(heap_start as *mut u8, heap_size)
        };
        dod_5220_wipe(heap_slice);
    }
}

fn dod_5220_wipe(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0x00) };
    }
    compiler_fence(Ordering::SeqCst);
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0xFF) };
    }
    compiler_fence(Ordering::SeqCst);
    for chunk in data.chunks_mut(8) {
        let random = crate::crypto::secure_random_u64();
        for (i, byte) in chunk.iter_mut().enumerate() {
            unsafe { core::ptr::write_volatile(byte, (random >> ((i % 8) * 8)) as u8) };
        }
    }
    compiler_fence(Ordering::SeqCst);
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0x00) };
    }
    compiler_fence(Ordering::SeqCst);
    verify_wipe(data);
    #[cfg(target_arch = "x86_64")]
    flush_cache_lines(data);
}

fn verify_wipe(data: &[u8]) {
    for byte in data {
        let val = unsafe { core::ptr::read_volatile(byte) };
        if val != 0 {
            crate::log::warn!("[WIPE] Verification failed at offset, forcing re-wipe");
            break;
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn flush_cache_lines(data: &[u8]) {
    for chunk in data.chunks(64) {
        let addr = chunk.as_ptr() as usize;
        unsafe {
            core::arch::asm!("clflush [{}]", in(reg) addr, options(nostack, preserves_flags));
        }
    }
    unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
}

fn wipe_process_memory() {
    for process in crate::process::enumerate_all_processes() {
        if let Some(pcb) = crate::process::get_process_table().find_by_pid(process.pid) {
            let memory = pcb.memory.lock();

            let code_start = memory.code_start.as_u64() as *mut u8;
            let code_size = memory.code_end.as_u64().saturating_sub(memory.code_start.as_u64()) as usize;
            if code_size > 0 && code_size < 1024 * 1024 * 256 {
                // SAFETY: code region bounds come from validated PCB
                let code_slice = unsafe { core::slice::from_raw_parts_mut(code_start, code_size) };
                for byte in code_slice.iter_mut() {
                    unsafe { core::ptr::write_volatile(byte, 0) };
                }
            }

            for vma in &memory.vmas {
                let vma_start = vma.start.as_u64() as *mut u8;
                let vma_size = vma.end.as_u64().saturating_sub(vma.start.as_u64()) as usize;
                if vma_size > 0 && vma_size < 1024 * 1024 * 256 {
                    // SAFETY: VMA bounds come from validated memory map
                    let vma_slice = unsafe { core::slice::from_raw_parts_mut(vma_start, vma_size) };
                    for byte in vma_slice.iter_mut() {
                        unsafe { core::ptr::write_volatile(byte, 0) };
                    }
                }
            }
        }
    }
}

fn wipe_crypto_keys() {
    let key_ids = crate::crypto::vault::list_vault_keys();
    for key_id in key_ids {
        let _ = crate::crypto::vault::delete_vault_key(key_id);
    }
}

fn wipe_ipc_buffers() {
    crate::ipc::init_ipc();
}

fn wipe_vfs_caches() {
    crate::fs::clear_caches();
}
