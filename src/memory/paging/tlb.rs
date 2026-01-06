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

use x86_64::{PhysAddr, VirtAddr};
use super::constants::PAGE_SIZE_4K;
#[inline]
pub fn invalidate_page(va: VirtAddr) {
    // SAFETY: INVLPG is always safe to execute
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) va.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub fn invalidate_all() {
    // SAFETY: Reading and writing CR3 is safe
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

pub fn invalidate_range(start: VirtAddr, page_count: usize) {
    // For large ranges, it's more efficient to flush entire TLB
    if page_count > 32 {
        invalidate_all();
        return;
    }

    for i in 0..page_count {
        let addr = VirtAddr::new(start.as_u64() + (i * PAGE_SIZE_4K) as u64);
        invalidate_page(addr);
    }
}

#[inline]
pub fn flush_address_space(cr3_value: PhysAddr) {
    // SAFETY: Loading valid page table into CR3
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3_value.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}
#[inline]
pub fn get_cr3() -> PhysAddr {
    let cr3: u64;
    // SAFETY: Reading CR3 is always safe
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    PhysAddr::new(cr3 & !0xFFF) // Mask out flags
}
#[inline]
pub fn set_cr3(page_table_pa: PhysAddr) {
    // SAFETY: Caller must ensure page_table_pa points to valid page table
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) page_table_pa.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}
// ============================================================================
// WRITE PROTECTION CONTROL
// ============================================================================
#[inline]
pub fn enable_write_protection() {
    // SAFETY: Modifying CR0 WP bit
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr0",
            "or {tmp:e}, 0x10000",
            "mov cr0, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}
/// # Safety
///
/// Caller must ensure this is only used temporarily for legitimate
/// kernel operations and re-enabled immediately after.
#[inline]
pub unsafe fn disable_write_protection() {
    core::arch::asm!(
        "mov {tmp}, cr0",
        "and {tmp:e}, 0xFFFEFFFF",
        "mov cr0, {tmp}",
        tmp = out(reg) _,
        options(nostack, preserves_flags)
    );
}
/// # Safety
///
/// Caller must ensure the closure only performs legitimate kernel
/// operations that require write protection bypass.
#[inline]
pub unsafe fn with_write_protection_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    disable_write_protection();
    let result = f();
    enable_write_protection();
    result
}
