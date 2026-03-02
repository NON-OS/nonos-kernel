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
use super::types::CpuDescriptor;
use super::state::{CPU_DESCRIPTORS, CPU_COUNT, BSP_APIC_ID};

#[inline]
pub fn cpu_id() -> usize {
    let apic_id = crate::arch::x86_64::interrupt::apic::id();
    apic_to_cpu_id(apic_id).unwrap_or(0)
}

pub fn apic_to_cpu_id(apic_id: u32) -> Option<usize> {
    for i in 0..CPU_COUNT.load(Ordering::Acquire) {
        if CPU_DESCRIPTORS[i].apic_id == apic_id {
            return Some(i);
        }
    }
    None
}

#[inline]
pub fn current_cpu() -> &'static CpuDescriptor {
    &CPU_DESCRIPTORS[cpu_id()]
}

pub fn get_cpu(id: usize) -> Option<&'static CpuDescriptor> {
    if id < CPU_COUNT.load(Ordering::Acquire) {
        Some(&CPU_DESCRIPTORS[id])
    } else {
        None
    }
}

#[inline]
pub fn is_bsp() -> bool {
    crate::arch::x86_64::interrupt::apic::id() == BSP_APIC_ID.load(Ordering::Acquire)
}
