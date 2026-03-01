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

use core::sync::atomic::Ordering;
use super::types::{SanitizationLevel, SanitizationStats};
use super::state::{INITIALIZED, SANITIZATION_LEVEL, BYTES_SANITIZED, SANITIZATION_CALLS};
use super::erase::{sanitize, dod_5220_erase};
use super::canary::{init_stack_canary, get_stack_canary};

pub fn on_free(ptr: *mut u8, size: usize) {
    if INITIALIZED.load(Ordering::Relaxed) {
        sanitize(ptr, size);
    }
}

pub fn on_realloc(old_ptr: *mut u8, old_size: usize) {
    if INITIALIZED.load(Ordering::Relaxed) {
        sanitize(old_ptr, old_size);
    }
}

pub fn sanitize_process_memory(pid: u64) {
    crate::log::info!("[SANITIZE] Sanitizing memory for process {}", pid);

    if let Some(pcb) = crate::process::get_process_table().find_by_pid(pid as u32) {
        let memory = pcb.memory.lock();

        let code_start = memory.code_start.as_u64() as *mut u8;
        let code_size = memory.code_end.as_u64().saturating_sub(memory.code_start.as_u64()) as usize;
        if code_size > 0 && code_size < 256 * 1024 * 1024 {
            sanitize(code_start, code_size);
        }

        for vma in &memory.vmas {
            let vma_start = vma.start.as_u64() as *mut u8;
            let vma_size = vma.end.as_u64().saturating_sub(vma.start.as_u64()) as usize;
            if vma_size > 0 && vma_size < 256 * 1024 * 1024 {
                sanitize(vma_start, vma_size);
            }
        }
    }
}

pub fn zerostate_shutdown_wipe() {
    crate::log::info!("[SANITIZE] ZeroState shutdown wipe initiated");

    let saved_level = SANITIZATION_LEVEL.load(Ordering::Relaxed);
    SANITIZATION_LEVEL.store(SanitizationLevel::Paranoid as u64, Ordering::SeqCst);

    for process in crate::process::enumerate_all_processes() {
        sanitize_process_memory(process.pid as u64);
    }

    let heap_start = crate::memory::layout::KHEAP_BASE as *mut u8;
    let heap_size = crate::memory::layout::KHEAP_SIZE as usize;
    if heap_size > 0 && heap_size < 512 * 1024 * 1024 {
        dod_5220_erase(heap_start, heap_size);
    }

    crate::crypto::vault::zeroize_all_keys();

    SANITIZATION_LEVEL.store(saved_level, Ordering::SeqCst);

    crate::log::info!("[SANITIZE] ZeroState shutdown wipe complete");
}

pub fn sanitization_stats() -> SanitizationStats {
    SanitizationStats {
        bytes_sanitized: BYTES_SANITIZED.load(Ordering::Relaxed),
        sanitization_calls: SANITIZATION_CALLS.load(Ordering::Relaxed),
        level: SanitizationLevel::from_u64(SANITIZATION_LEVEL.load(Ordering::Relaxed)),
        canary_enabled: true,
    }
}

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    crate::log::info!("[SECURITY] Initializing memory sanitization...");

    init_stack_canary();

    SANITIZATION_LEVEL.store(SanitizationLevel::Standard as u64, Ordering::SeqCst);

    crate::log::info!("[SECURITY] Memory sanitization initialized");
    crate::log::info!("  Level: {:?}", SanitizationLevel::Standard);
    crate::log::info!("  Stack canary: 0x{:016X}", get_stack_canary());

    Ok(())
}

pub fn set_level(level: SanitizationLevel) {
    SANITIZATION_LEVEL.store(level as u64, Ordering::SeqCst);
    crate::log::info!("[SECURITY] Sanitization level set to {:?}", level);
}

pub fn get_level() -> SanitizationLevel {
    SanitizationLevel::from_u64(SANITIZATION_LEVEL.load(Ordering::Relaxed))
}
