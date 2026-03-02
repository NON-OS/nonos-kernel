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
use crate::memory::nonos_layout as layout;
use super::types::CpuState;
use super::constants::{MAX_CPUS, PERCPU_STACK_SIZE, AP_TRAMPOLINE_ADDR};
use super::state::{CPU_DESCRIPTORS, CPU_COUNT, CPUS_ONLINE, BSP_APIC_ID, SMP_INITIALIZED};
use super::topology;

pub fn init_bsp() -> Result<(), &'static str> {
    if SMP_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    let bsp_apic = crate::arch::x86_64::interrupt::apic::id();
    BSP_APIC_ID.store(bsp_apic, Ordering::Release);

    let bsp = &CPU_DESCRIPTORS[0];
    // SAFETY: Single-threaded BSP initialization
    unsafe {
        let ptr = bsp as *const _ as *mut super::types::CpuDescriptor;
        (*ptr).cpu_id = 0;
        (*ptr).apic_id = bsp_apic;
        (*ptr).numa_node = 0;
    }
    bsp.set_state(CpuState::Online);

    let cpu_count = topology::detect_cpus();
    CPU_COUNT.store(cpu_count, Ordering::Release);

    crate::log_info!("[SMP] BSP initialized: APIC ID={}, {} CPUs detected", bsp_apic, cpu_count);

    SMP_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub fn start_aps() -> Result<usize, &'static str> {
    if !SMP_INITIALIZED.load(Ordering::Acquire) {
        return Err("SMP not initialized");
    }

    let cpu_count = CPU_COUNT.load(Ordering::Acquire);
    if cpu_count <= 1 {
        crate::log_info!("[SMP] Single CPU system, no APs to start");
        return Ok(0);
    }

    setup_ap_trampoline()?;

    let mut started = 0;
    let ap_list = topology::get_ap_list();

    for &apic_id in &ap_list {
        if apic_id == BSP_APIC_ID.load(Ordering::Acquire) {
            continue;
        }

        let cpu_id = started + 1;
        if cpu_id >= MAX_CPUS {
            break;
        }

        let stack_base = allocate_cpu_stack(cpu_id)?;

        let ap = &CPU_DESCRIPTORS[cpu_id];
        // SAFETY: Single-threaded AP descriptor initialization
        unsafe {
            let ptr = ap as *const _ as *mut super::types::CpuDescriptor;
            (*ptr).cpu_id = cpu_id as u32;
            (*ptr).apic_id = apic_id;
            (*ptr).stack_size = PERCPU_STACK_SIZE;
        }
        ap.stack_base.store(stack_base, Ordering::Release);
        ap.set_state(CpuState::Starting);

        crate::arch::x86_64::interrupt::apic::start_ap(apic_id, (AP_TRAMPOLINE_ADDR >> 12) as u8);

        let timeout = 100_000_000u64;
        let start = read_tsc();
        while ap.state() != CpuState::Online {
            if read_tsc() - start > timeout {
                crate::log_error!("[SMP] AP {} (APIC {}) startup timeout", cpu_id, apic_id);
                ap.set_state(CpuState::Offline);
                break;
            }
            core::hint::spin_loop();
        }

        if ap.is_online() {
            started += 1;
            crate::log_info!("[SMP] AP {} online (APIC {})", cpu_id, apic_id);
        }
    }

    CPUS_ONLINE.store(started + 1, Ordering::Release);
    crate::log_info!("[SMP] {} APs started, {} total CPUs online", started, started + 1);

    Ok(started)
}

fn setup_ap_trampoline() -> Result<(), &'static str> {
    if AP_TRAMPOLINE_ADDR >= 0x100000 {
        return Err("AP trampoline address must be < 1MB");
    }
    Ok(())
}

fn allocate_cpu_stack(cpu_id: usize) -> Result<u64, &'static str> {
    let stack_base = layout::PERCPU_STACKS_BASE + (cpu_id as u64 * PERCPU_STACK_SIZE as u64);

    let pages = PERCPU_STACK_SIZE / layout::PAGE_SIZE;
    for i in 0..pages {
        let va = VirtAddr::new(stack_base + (i * layout::PAGE_SIZE) as u64);

        if let Some(pa) = crate::memory::nonos_frame_alloc::allocate_frame() {
            crate::memory::nonos_virt::map_page_4k(va, pa, true, false, false)
                .map_err(|_| "Failed to map CPU stack page")?;
        } else {
            return Err("Failed to allocate CPU stack frame");
        }
    }

    Ok(stack_base)
}

#[inline]
fn read_tsc() -> u64 {
    // SAFETY: rdtsc is always safe
    unsafe { core::arch::x86_64::_rdtsc() }
}
