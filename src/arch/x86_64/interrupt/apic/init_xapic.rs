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

use crate::memory::addr::PhysAddr;
use core::sync::atomic::Ordering;

use super::constants::*;
use super::error::ApicResult;
use super::mmio::{map_apic_mmio, mmio_w32};
use super::state::*;
use crate::memory::layout::PAGE_SIZE;
use crate::memory::paging::types::PagePermissions;
use crate::memory::proof::{self, CapTag};

pub(super) unsafe fn init_xapic() -> ApicResult<()> {
    unsafe {
        let phys = (rdmsr(IA32_APIC_BASE) & 0xFFFF_F000) as u64;
        let va = map_apic_mmio(PhysAddr::new(phys))?;
        MMIO_BASE.store(va.as_u64(), Ordering::Release);

        mmio_w32(LAPIC_SVR, SVR_APIC_ENABLE | VEC_SPURIOUS as u32);
        mmio_w32(LAPIC_LVT_LINT0, LVT_NMI);
        mmio_w32(LAPIC_LVT_LINT1, LVT_MASKED | LVT_LEVEL);
        mmio_w32(LAPIC_LVT_THERM, VEC_THERMAL as u32);
        mmio_w32(LAPIC_LVT_ERROR, VEC_ERROR as u32);
        mmio_w32(LAPIC_LVT_TIMER, LVT_MASKED);

        let audit_flags = (PagePermissions::READ
            | PagePermissions::WRITE
            | PagePermissions::GLOBAL
            | PagePermissions::NO_CACHE)
            .to_pte_flags();
        proof::audit_map(va.as_u64(), phys, PAGE_SIZE as u64, audit_flags, CapTag::KERNEL);
        Ok(())
    }
}
