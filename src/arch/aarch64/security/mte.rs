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
pub enum MteMode {
    Disabled,
    Synchronous,
    Asynchronous,
    Asymmetric,
}

pub fn init_mte() {
    if !has_feature(CpuFeature::Mte) {
        return;
    }

    configure_tcr_mte();
    configure_sctlr_mte();
    configure_gcr();
}

fn configure_tcr_mte() {
    unsafe {
        let mut tcr: u64;
        asm!("mrs {}, tcr_el1", out(reg) tcr);

        tcr |= 1 << 37;
        tcr |= 1 << 38;

        asm!(
            "msr tcr_el1, {}",
            "isb",
            in(reg) tcr
        );
    }
}

fn configure_sctlr_mte() {
    unsafe {
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        sctlr |= 1 << 43;

        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr
        );
    }
}

fn configure_gcr() {
    let gcr: u64 = 0xFFFF << 1;
    unsafe {
        asm!(
            "msr gcr_el1, {}",
            "isb",
            in(reg) gcr
        );
    }
}

pub fn set_mte_mode(mode: MteMode) {
    if !has_feature(CpuFeature::Mte) {
        return;
    }

    let tcf = match mode {
        MteMode::Disabled => 0b00,
        MteMode::Synchronous => 0b01,
        MteMode::Asynchronous => 0b10,
        MteMode::Asymmetric => 0b11,
    };

    unsafe {
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        sctlr &= !(0b11 << 40);
        sctlr |= (tcf as u64) << 40;

        sctlr &= !(0b11 << 38);
        sctlr |= (tcf as u64) << 38;

        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr
        );
    }
}

pub fn mte_enabled() -> bool {
    has_feature(CpuFeature::Mte)
}

pub fn generate_tag() -> u8 {
    let tag: u64;
    unsafe {
        asm!(
            "irg {0}, {0}",
            inout(reg) 0u64 => tag
        );
    }
    ((tag >> 56) & 0xF) as u8
}

pub fn set_tag(ptr: *mut u8, tag: u8) {
    let tagged_ptr = (ptr as u64 & 0x00FF_FFFF_FFFF_FFFF) | ((tag as u64) << 56);
    unsafe {
        asm!(
            "stg {0}, [{0}]",
            in(reg) tagged_ptr
        );
    }
}

pub fn check_tag(ptr: *const u8) -> bool {
    let result: u64;
    unsafe {
        asm!(
            "ldg {0}, [{0}]",
            inout(reg) ptr as u64 => result
        );
    }
    (result >> 56) & 0xF == (ptr as u64 >> 56) & 0xF
}

pub fn clear_tag(ptr: *mut u8, size: usize) {
    let aligned_ptr = (ptr as u64) & !0xF;
    let granules = (size + 15) / 16;

    for i in 0..granules {
        let addr = aligned_ptr + (i as u64 * 16);
        unsafe {
            asm!(
                "stzg xzr, [{0}]",
                in(reg) addr
            );
        }
    }
}
