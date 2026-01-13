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

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use super::types::MAX_PCID;
use super::tlb::flush_tlb_pcid;

const CR4_PCIDE: u64 = 1 << 17;

pub const KERNEL_PCID: u16 = 0;

static PCID_BITMAP: Mutex<[u64; 64]> = Mutex::new([0; 64]); // 64 * 64 = 4096 bits
static PCID_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn pcid_enabled() -> bool {
    PCID_ENABLED.load(Ordering::Relaxed)
}

pub fn enable_pcid() {
    // # SAFETY: __cpuid is safe to call on x86_64  it only reads CPU feature information.
    let cpuid = unsafe { core::arch::x86_64::__cpuid(1) };
    if cpuid.ecx & (1 << 17) == 0 {
        crate::log::log_warning!("[ADDR_SPACE] PCID not supported by CPU");
        return;
    }
    // # SAFETY: CR4 register manipulation is safe when:
    // 1. We are in ring 0 (kernel mode) - always true in kernel code
    // 2. We have verified PCID support via CPUID above
    // 3. The PCIDE bit only enables a performance optimization feature
    // # The nomem/nostack options are correct as these are pure register operations.
    unsafe {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        core::arch::asm!("mov cr4, {}", in(reg) cr4 | CR4_PCIDE, options(nostack));
    }

    PCID_ENABLED.store(true, Ordering::SeqCst);
    crate::log::info!("[ADDR_SPACE] PCID enabled");
}

pub fn allocate_pcid() -> u16 {
    let mut bitmap = PCID_BITMAP.lock();
    // ## PCID 0 is reserved for kernel ##
    for i in 1..MAX_PCID {
        let word_idx = (i / 64) as usize;
        let bit_idx = i % 64;

        if bitmap[word_idx] & (1u64 << bit_idx) == 0 {
            bitmap[word_idx] |= 1u64 << bit_idx;
            return i;
        }
    }

    crate::log::log_warning!("[ADDR_SPACE] PCID exhausted, sharing with kernel");
    0
}

pub fn release_pcid(pcid: u16) {
    if pcid == 0 {
        return; // Kernel PCID
    }

    let mut bitmap = PCID_BITMAP.lock();
    let word_idx = (pcid / 64) as usize;
    let bit_idx = pcid % 64;
    bitmap[word_idx] &= !(1u64 << bit_idx);

    flush_tlb_pcid(pcid);
}
