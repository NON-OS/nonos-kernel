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

use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::state::*;
use super::mmio::{mmio_r32, mmio_w32};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

pub fn timer_enable(hz: u32, divider: u8) -> TimerMode {
    if TSC_DEADLINE_MODE.load(Ordering::Acquire) {
        if X2APIC_MODE.load(Ordering::Acquire) {
            wrmsr(IA32_X2APIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE as u64 | VEC_TIMER as u64);
        } else {
            mmio_w32(LAPIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE | VEC_TIMER as u32);
        }
        proof::audit_phys_alloc(0xDEAD_1000u64, 1, CapTag::KERNEL);
        return TimerMode::TscDeadline;
    }

    let div_code = divider_to_code(divider);
    let init_count = calibrate_timer(hz);

    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_DIV, div_code as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, LVT_TIMER_PERIODIC as u64 | VEC_TIMER as u64);
        wrmsr(IA32_X2APIC_INITCNT, init_count as u64);
    } else {
        mmio_w32(LAPIC_DIV, div_code);
        mmio_w32(LAPIC_LVT_TIMER, LVT_TIMER_PERIODIC | VEC_TIMER as u32);
        mmio_w32(LAPIC_INITCNT, init_count);
    }

    proof::audit_phys_alloc(0xFEE00000u64, hz as u64, CapTag::KERNEL);
    TimerMode::Periodic
}

pub fn timer_oneshot(ticks: u32, divider: u8) {
    let div_code = divider_to_code(divider);

    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_DIV, div_code as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64);
        wrmsr(IA32_X2APIC_INITCNT, ticks as u64);
    } else {
        mmio_w32(LAPIC_DIV, div_code);
        mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32);
        mmio_w32(LAPIC_INITCNT, ticks);
    }
}

#[inline]
pub fn timer_deadline_tsc(tsc: u64) {
    wrmsr(IA32_TSC_DEADLINE, tsc);
}

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

pub fn timer_current() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        rdmsr(IA32_X2APIC_CURRCNT) as u32
    } else {
        mmio_r32(LAPIC_CURRCNT)
    }
}

pub fn divider_to_code(div: u8) -> u32 {
    match div {
        1 => 0b1011, 2 => 0b0000, 4 => 0b0001, 8 => 0b0010, 16 => 0b0011,
        32 => 0b1000, 64 => 0b1001, 128 => 0b1010, _ => 0b0011,
    }
}

pub fn calibrate_timer(hz: u32) -> u32 {
    let mut init = 10_000_000u32;
    if hz >= 1000 { init /= (hz / 1000).max(1); }
    init.max(50_000)
}
