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
use x86_64::VirtAddr;
use super::constants::IPI_TLB_SHOOTDOWN;
use super::state::{cpus_online, TLB_SHOOTDOWN_ACTIVE, TLB_SHOOTDOWN_ADDR, TLB_SHOOTDOWN_ACK};

pub fn tlb_shootdown(addr: VirtAddr) {
    if cpus_online() <= 1 {
        // SAFETY: Single CPU, just invalidate locally
        unsafe { invalidate_page(addr); }
        return;
    }

    TLB_SHOOTDOWN_ADDR.store(addr.as_u64(), Ordering::Release);
    TLB_SHOOTDOWN_ACK.store(0, Ordering::Release);
    TLB_SHOOTDOWN_ACTIVE.store(true, Ordering::Release);

    crate::arch::x86_64::interrupt::apic::ipi_others(IPI_TLB_SHOOTDOWN);

    // SAFETY: Invalidating TLB entry for given address
    unsafe { invalidate_page(addr); }

    let expected = cpus_online() as u32 - 1;
    let timeout = 10_000_000u64;
    let start = read_tsc();

    while TLB_SHOOTDOWN_ACK.load(Ordering::Acquire) < expected {
        if read_tsc() - start > timeout {
            crate::log_error!("[SMP] TLB shootdown timeout");
            break;
        }
        core::hint::spin_loop();
    }

    TLB_SHOOTDOWN_ACTIVE.store(false, Ordering::Release);
}

pub fn handle_tlb_shootdown_ipi() {
    if TLB_SHOOTDOWN_ACTIVE.load(Ordering::Acquire) {
        let addr = VirtAddr::new(TLB_SHOOTDOWN_ADDR.load(Ordering::Acquire));
        // SAFETY: Invalidating TLB entry for shootdown address
        unsafe { invalidate_page(addr); }
        TLB_SHOOTDOWN_ACK.fetch_add(1, Ordering::Release);
    }
}

#[inline]
unsafe fn invalidate_page(addr: VirtAddr) {
    // SAFETY: invlpg is safe for any valid virtual address
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags)); }
}

#[inline]
pub unsafe fn flush_tlb() {
    unsafe {
        // SAFETY: Reloading CR3 flushes the entire TLB
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

#[inline]
fn read_tsc() -> u64 {
    // SAFETY: rdtsc is always safe
    unsafe { core::arch::x86_64::_rdtsc() }
}
