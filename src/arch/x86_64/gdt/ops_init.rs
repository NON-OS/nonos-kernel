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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use crate::arch::x86_64::gdt::constants::MAX_CPUS;
use crate::arch::x86_64::gdt::error::GdtError;
use crate::arch::x86_64::gdt::state::*;

pub fn init() -> Result<(), GdtError> {
    if !INITIALIZING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        while !INITIALIZED.load(Ordering::Acquire) { core::hint::spin_loop(); }
        return Err(GdtError::AlreadyInitialized);
    }
    unsafe {
        let gdt = addr_of_mut!(BSP_GDT);
        (*gdt).init(0);
        (*gdt).load()?;
        GDT_LOADS.fetch_add(1, Ordering::Relaxed);
        TSS_LOADS.fetch_add(1, Ordering::Relaxed);
        CPU_COUNT.store(1, Ordering::Release);
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub unsafe fn init_ap(cpu_id: u32) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS { return Err(GdtError::InvalidCpuId); }
    if cpu_id == 0 { return Ok(()); }
    unsafe {
        let idx = cpu_id as usize - 1;
        let gdts = addr_of_mut!(AP_GDTS);
        (*gdts)[idx].init(cpu_id);
        (*gdts)[idx].load()?;
        GDT_LOADS.fetch_add(1, Ordering::Relaxed);
        TSS_LOADS.fetch_add(1, Ordering::Relaxed);
        CPU_COUNT.fetch_add(1, Ordering::Release);
    }
    Ok(())
}

#[inline]
pub fn is_initialized() -> bool { INITIALIZED.load(Ordering::Acquire) }
