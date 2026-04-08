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
use super::constants::*;
use super::state::*;
use super::mmio::{mmio_r32, mmio_w32};

pub fn ipi_self(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_SELF | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_SELF as u32 | vec as u32);
    }
}

pub fn ipi_one(apic_id: u32, vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, (apic_id as u64) << 32 | ICR_DELIV_FIXED |
            ICR_DST_PHYSICAL | ICR_SH_NONE | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, apic_id << 24);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

pub fn ipi_all(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_ALL | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_ALL as u32 | vec as u32);
    }
}

pub fn ipi_others(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_OTHERS | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_OTHERS as u32 | vec as u32);
    }
}

pub(super) fn wait_icr_idle() {
    for _ in 0..100_000 {
        if (mmio_r32(LAPIC_ICR_LOW) & ICR_BUSY) == 0 { return; }
        core::hint::spin_loop();
    }
}
