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

use core::arch::asm;

use super::super::cpu::features::{has_feature, CpuFeature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreMitigation {
    None,
    Ssbs,
    CsvEnabled,
    BranchTargetId,
}

pub fn init_spectre_mitigations() {
    if has_feature(CpuFeature::Ssbs) {
        enable_ssbs();
    }

    speculative_barrier();
}

fn enable_ssbs() {
    unsafe {
        asm!("msr ssbs, {}", in(reg) 1u64);
    }
}

fn disable_ssbs() {
    unsafe {
        asm!("msr ssbs, {}", in(reg) 0u64);
    }
}

pub fn speculative_barrier() {
    unsafe {
        asm!("sb", options(nomem, nostack));
    }
}

pub fn speculation_safe_load<T: Copy>(ptr: *const T) -> T {
    let value: T;
    unsafe {
        value = *ptr;
        asm!("csdb", options(nomem, nostack));
    }
    value
}

pub fn clear_prediction_state() {
    if has_feature(CpuFeature::Sb) {
        unsafe {
            asm!("sb", options(nomem, nostack));
        }
    } else {
        unsafe {
            asm!("dsb sy", "isb", options(nomem, nostack));
        }
    }
}

pub fn is_csv2_enabled() -> bool {
    let aa64pfr0: u64;
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) aa64pfr0);
    }

    let csv2 = (aa64pfr0 >> 56) & 0xF;
    csv2 >= 1
}

pub fn is_csv3_enabled() -> bool {
    let aa64pfr0: u64;
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) aa64pfr0);
    }

    let csv3 = (aa64pfr0 >> 60) & 0xF;
    csv3 >= 1
}

pub fn mitigations_active() -> Vec<SpectreMitigation> {
    let mut active = alloc::vec::Vec::new();

    if has_feature(CpuFeature::Ssbs) {
        active.push(SpectreMitigation::Ssbs);
    }

    if is_csv2_enabled() {
        active.push(SpectreMitigation::CsvEnabled);
    }

    if has_feature(CpuFeature::Bti) {
        active.push(SpectreMitigation::BranchTargetId);
    }

    if active.is_empty() {
        active.push(SpectreMitigation::None);
    }

    active
}

pub fn enter_kernel() {
    if has_feature(CpuFeature::Ssbs) {
        enable_ssbs();
    }
}

pub fn exit_kernel() {
    if has_feature(CpuFeature::Ssbs) {
        disable_ssbs();
    }
}

use alloc::vec::Vec;
