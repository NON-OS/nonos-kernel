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

use super::constants::*;
use super::mmio::{mmio_r32, mmio_w32};
use super::state::*;
use core::sync::atomic::Ordering;

pub fn timer_mask() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        let val = rdmsr(IA32_X2APIC_LVT_TIMER) as u32 | LVT_MASKED;
        wrmsr(IA32_X2APIC_LVT_TIMER, val as u64);
    } else {
        let val = mmio_r32(LAPIC_LVT_TIMER) | LVT_MASKED;
        mmio_w32(LAPIC_LVT_TIMER, val);
    }
}

pub fn timer_unmask() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        let val = rdmsr(IA32_X2APIC_LVT_TIMER) as u32 & !LVT_MASKED;
        wrmsr(IA32_X2APIC_LVT_TIMER, val as u64);
    } else {
        let val = mmio_r32(LAPIC_LVT_TIMER) & !LVT_MASKED;
        mmio_w32(LAPIC_LVT_TIMER, val);
    }
}
