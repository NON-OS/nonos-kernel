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
use crate::arch::x86_64::gdt::constants::MAX_CPUS;
use crate::arch::x86_64::gdt::error::GdtError;
use crate::arch::x86_64::gdt::state::*;

pub unsafe fn set_kernel_stack(cpu_id: u32, rsp: u64) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS { return Err(GdtError::InvalidCpuId); }
    unsafe {
        if cpu_id == 0 {
            let gdt = addr_of_mut!(BSP_GDT);
            (*gdt).tss.set_rsp0(rsp);
        } else {
            let idx = cpu_id as usize - 1;
            let gdts = addr_of_mut!(AP_GDTS);
            (*gdts)[idx].tss.set_rsp0(rsp);
        }
    }
    Ok(())
}

pub fn get_kernel_stack(cpu_id: u32) -> Result<u64, GdtError> {
    if cpu_id as usize >= MAX_CPUS { return Err(GdtError::InvalidCpuId); }
    unsafe {
        if cpu_id == 0 {
            let gdt = addr_of_mut!(BSP_GDT);
            Ok((*gdt).tss.rsp0())
        } else {
            let idx = cpu_id as usize - 1;
            let gdts = addr_of_mut!(AP_GDTS);
            Ok((*gdts)[idx].tss.rsp0())
        }
    }
}

pub unsafe fn set_ist(cpu_id: u32, ist_index: usize, stack_top: u64) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS { return Err(GdtError::InvalidCpuId); }
    unsafe {
        if cpu_id == 0 {
            let gdt = addr_of_mut!(BSP_GDT);
            (*gdt).tss.set_ist(ist_index, stack_top)
        } else {
            let idx = cpu_id as usize - 1;
            let gdts = addr_of_mut!(AP_GDTS);
            (*gdts)[idx].tss.set_ist(ist_index, stack_top)
        }
    }
}

pub fn get_ist(cpu_id: u32, ist_index: usize) -> Result<u64, GdtError> {
    if cpu_id as usize >= MAX_CPUS { return Err(GdtError::InvalidCpuId); }
    unsafe {
        if cpu_id == 0 {
            let gdt = addr_of_mut!(BSP_GDT);
            (*gdt).tss.get_ist(ist_index)
        } else {
            let idx = cpu_id as usize - 1;
            let gdts = addr_of_mut!(AP_GDTS);
            (*gdts)[idx].tss.get_ist(ist_index)
        }
    }
}
