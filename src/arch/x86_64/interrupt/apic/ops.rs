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

pub fn id() -> u32 {
    CACHED_ID.load(Ordering::Acquire)
}

pub fn read_id_internal() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        (rdmsr(IA32_X2APIC_APICID) & 0xFFFF_FFFF) as u32
    } else {
        (mmio_r32(LAPIC_ID) >> 24) & 0xFF
    }
}

pub fn set_tpr(priority: u8) {
    CURRENT_TPR.store(priority, Ordering::Release);
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_TPR, priority as u64);
    } else {
        mmio_w32(LAPIC_TPR, priority as u32);
    }
}

pub fn get_tpr() -> u8 {
    CURRENT_TPR.load(Ordering::Acquire)
}

#[inline(always)]
pub fn eoi() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_EOI, 0);
    } else {
        mmio_w32(LAPIC_EOI, 0);
    }
}

pub fn send_eoi() {
    eoi();
}

pub fn version() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        (rdmsr(0x803) & 0xFF) as u32
    } else {
        mmio_r32(LAPIC_VER) & 0xFF
    }
}

pub fn max_lvt() -> u8 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        ((rdmsr(0x803) >> 16) & 0xFF) as u8
    } else {
        ((mmio_r32(LAPIC_VER) >> 16) & 0xFF) as u8
    }
}

#[derive(Debug, Clone)]
pub struct ApicStatus {
    pub initialized: bool,
    pub x2apic: bool,
    pub tsc_deadline: bool,
    pub id: u32,
    pub version: u32,
    pub max_lvt: u8,
    pub tpr: u8,
}

pub fn status() -> ApicStatus {
    ApicStatus {
        initialized: is_initialized(),
        x2apic: is_x2apic(),
        tsc_deadline: supports_tsc_deadline(),
        id: id(),
        version: if is_initialized() { version() } else { 0 },
        max_lvt: if is_initialized() { max_lvt() } else { 0 },
        tpr: get_tpr(),
    }
}
