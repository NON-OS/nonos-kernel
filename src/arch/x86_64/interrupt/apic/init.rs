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
use x86_64::PhysAddr;

use crate::memory::virt::VmFlags;
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::error::{ApicError, ApicResult};
use super::state::*;
use super::mmio::{mmio_w32, map_apic_mmio};
use super::ops::{set_tpr, read_id_internal};

pub unsafe fn init() -> ApicResult<()> {
    unsafe {
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(ApicError::AlreadyInitialized);
        }

        if !has_xapic() {
            INITIALIZED.store(false, Ordering::SeqCst);
            return Err(ApicError::NotSupported);
        }

        let mut base = rdmsr(IA32_APIC_BASE);
        base |= APIC_BASE_ENABLE;
        wrmsr(IA32_APIC_BASE, base);

        if has_x2apic() {
            wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | APIC_BASE_X2);
            X2APIC_MODE.store(true, Ordering::Release);
            init_x2apic();
        } else {
            X2APIC_MODE.store(false, Ordering::Release);
            init_xapic()?;
        }

        set_tpr(0);
        TSC_DEADLINE_MODE.store(has_tsc_deadline(), Ordering::Release);

        let apic_id = read_id_internal();
        CACHED_ID.store(apic_id, Ordering::Release);

        proof::audit_phys_alloc(0xA11C_0000, 0x1017_u64, CapTag::KERNEL);

        crate::log::logger::log_info!(
            "[APIC] mode={} id={} tsc_deadline={}",
            if is_x2apic() { "x2APIC" } else { "xAPIC" },
            apic_id,
            supports_tsc_deadline()
        );

        Ok(())
    }
}

fn init_x2apic() {
    let svr = SVR_APIC_ENABLE as u64 | VEC_SPURIOUS as u64 | SVR_EOI_SUPPRESS as u64;
    wrmsr(IA32_X2APIC_SVR, svr);

    wrmsr(IA32_X2APIC_LVT_LINT0, LVT_NMI as u64);
    wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64);
    wrmsr(IA32_X2APIC_LVT_THERM, LVT_FIXED as u64 | VEC_THERMAL as u64);
    wrmsr(IA32_X2APIC_LVT_ERROR, LVT_FIXED as u64 | VEC_ERROR as u64);
    wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
}

unsafe fn init_xapic() -> ApicResult<()> {
    unsafe {
        let phys = (rdmsr(IA32_APIC_BASE) & 0xFFFF_F000) as u64;
        let va = map_apic_mmio(PhysAddr::new(phys))?;
        MMIO_BASE.store(va.as_u64() as u32, Ordering::Release);

        mmio_w32(LAPIC_SVR, SVR_APIC_ENABLE | VEC_SPURIOUS as u32);
        mmio_w32(LAPIC_LVT_LINT0, LVT_NMI);
        mmio_w32(LAPIC_LVT_LINT1, LVT_MASKED | LVT_LEVEL);
        mmio_w32(LAPIC_LVT_THERM, VEC_THERMAL as u32);
        mmio_w32(LAPIC_LVT_ERROR, VEC_ERROR as u32);
        mmio_w32(LAPIC_LVT_TIMER, LVT_MASKED);

        proof::audit_map(
            va.as_u64(), phys, PAGE_SIZE as u64,
            (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(),
            CapTag::KERNEL,
        );

        Ok(())
    }
}

pub fn init_apic() -> ApicResult<()> {
    unsafe { init() }
}
