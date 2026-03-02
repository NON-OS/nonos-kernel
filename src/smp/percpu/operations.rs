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
use x86_64::registers::model_specific::{GsBase, KernelGsBase};
use x86_64::VirtAddr;

use crate::smp::{MAX_CPUS, cpu_id};
use super::types::PerCpuData;

static mut PERCPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new();
    [INIT; MAX_CPUS]
};

pub fn init_bsp() {
    // SAFETY: Single-threaded BSP initialization
    unsafe {
        let data = &mut PERCPU_DATA[0];
        data.self_ptr = data as *const PerCpuData as u64;
        data.cpu_id = 0;
        data.apic_id = crate::arch::x86_64::interrupt::apic::id();
        data.random_state.store(read_tsc(), Ordering::Relaxed);

        GsBase::write(VirtAddr::new(data.self_ptr));
        KernelGsBase::write(VirtAddr::new(data.self_ptr));
    }
}

pub fn init_ap(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    // SAFETY: Each AP initializes only its own per-CPU data
    unsafe {
        let data = &mut PERCPU_DATA[cpu_id];
        data.self_ptr = data as *const PerCpuData as u64;
        data.cpu_id = cpu_id as u32;
        data.apic_id = crate::arch::x86_64::interrupt::apic::id();
        data.random_state.store(read_tsc().wrapping_mul(cpu_id as u64 + 1), Ordering::Relaxed);

        GsBase::write(VirtAddr::new(data.self_ptr));
        KernelGsBase::write(VirtAddr::new(data.self_ptr));
    }
}

#[inline]
pub fn current() -> &'static PerCpuData {
    // SAFETY: cpu_id returns valid index, data is initialized
    unsafe { &PERCPU_DATA[cpu_id()] }
}

#[inline]
pub unsafe fn current_mut() -> &'static mut PerCpuData {
    // SAFETY: Caller ensures exclusive access
    unsafe { &mut PERCPU_DATA[cpu_id()] }
}

pub fn get(id: usize) -> Option<&'static PerCpuData> {
    if id < MAX_CPUS {
        // SAFETY: Index is bounds-checked
        unsafe { Some(&PERCPU_DATA[id]) }
    } else {
        None
    }
}

pub fn set_kernel_stack(stack_top: u64) {
    // SAFETY: Modifying current CPU's data only
    unsafe {
        PERCPU_DATA[cpu_id()].kernel_stack_top = stack_top;
    }
}

#[inline]
pub fn kernel_stack() -> u64 {
    current().kernel_stack_top
}

pub fn set_current_process(ptr: u64) {
    current().current_process.store(ptr, Ordering::Release);
}

#[inline]
pub fn current_process() -> u64 {
    current().current_process.load(Ordering::Acquire)
}

pub fn set_current_thread(ptr: u64) {
    current().current_thread.store(ptr, Ordering::Release);
}

#[inline]
pub fn current_thread() -> u64 {
    current().current_thread.load(Ordering::Acquire)
}

#[inline]
pub fn enter_irq() {
    // SAFETY: Modifying current CPU's data only
    unsafe {
        PERCPU_DATA[cpu_id()].irq_nesting += 1;
    }
}

#[inline]
pub fn leave_irq() {
    // SAFETY: Modifying current CPU's data only
    unsafe {
        let data = &mut PERCPU_DATA[cpu_id()];
        if data.irq_nesting > 0 {
            data.irq_nesting -= 1;
        }
    }
}

#[inline]
pub fn in_irq() -> bool {
    current().irq_nesting > 0
}

pub fn percpu_random() -> u64 {
    let data = current();
    let old = data.random_state.load(Ordering::Relaxed);
    let mut x = old;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    data.random_state.store(x, Ordering::Relaxed);
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

#[inline]
fn read_tsc() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64
    unsafe { core::arch::x86_64::_rdtsc() }
}
