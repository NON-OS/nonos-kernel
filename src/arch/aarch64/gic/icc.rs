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

const ICC_SRE_SRE: u64 = 1 << 0;
const ICC_SRE_DFB: u64 = 1 << 1;
const ICC_SRE_DIB: u64 = 1 << 2;
const ICC_SRE_ENABLE: u64 = 1 << 3;

const ICC_CTLR_EOIMODE: u64 = 1 << 1;

const ICC_PMR_DEFAULT: u64 = 0xFF;

pub fn init() {
    enable_system_register_access();
    set_priority_mask(0xFF);
    enable_group1();
}

fn enable_system_register_access() {
    let sre = ICC_SRE_SRE | ICC_SRE_DFB | ICC_SRE_DIB | ICC_SRE_ENABLE;
    unsafe {
        asm!(
            "msr icc_sre_el1, {0}",
            "isb",
            in(reg) sre,
        );
    }
}

pub fn set_priority_mask(priority: u8) {
    unsafe {
        asm!(
            "msr icc_pmr_el1, {0}",
            "isb",
            in(reg) priority as u64,
        );
    }
}

fn enable_group1() {
    unsafe {
        asm!(
            "msr icc_igrpen1_el1, {0}",
            "isb",
            in(reg) 1u64,
        );
    }
}

pub fn acknowledge_interrupt() -> Option<u32> {
    let iar: u64;
    unsafe {
        asm!(
            "mrs {0}, icc_iar1_el1",
            out(reg) iar,
        );
    }

    let intid = (iar & 0xFFFFFF) as u32;

    if intid >= 1020 {
        None
    } else {
        Some(intid)
    }
}

pub fn end_interrupt(intid: u32) {
    unsafe {
        asm!(
            "msr icc_eoir1_el1, {0}",
            "isb",
            in(reg) intid as u64,
        );
    }
}

pub fn drop_priority(intid: u32) {
    unsafe {
        asm!(
            "msr icc_dir_el1, {0}",
            in(reg) intid as u64,
        );
    }
}

pub fn send_sgi(target: u32, intid: u32) -> Result<(), ()> {
    if intid >= 16 {
        return Err(());
    }

    let aff = target_to_affinity(target);
    let sgi_val = ((intid as u64) << 24) | (aff & 0xFFFF) | ((aff & 0xFF0000) << 16);

    unsafe {
        asm!(
            "msr icc_sgi1r_el1, {0}",
            "isb",
            in(reg) sgi_val,
        );
    }

    Ok(())
}

fn target_to_affinity(target: u32) -> u64 {
    let target_list = 1u64 << (target & 0xF);
    let aff1 = ((target >> 4) & 0xFF) as u64;
    let aff2 = ((target >> 12) & 0xFF) as u64;
    let aff3 = ((target >> 20) & 0xFF) as u64;

    target_list | (aff1 << 16) | (aff2 << 32) | (aff3 << 48)
}

pub fn running_priority() -> u8 {
    let rpr: u64;
    unsafe {
        asm!(
            "mrs {0}, icc_rpr_el1",
            out(reg) rpr,
        );
    }
    rpr as u8
}

pub fn highest_pending_priority() -> u8 {
    let hppir: u64;
    unsafe {
        asm!(
            "mrs {0}, icc_hppir1_el1",
            out(reg) hppir,
        );
    }
    (hppir >> 24) as u8
}

pub fn binary_point() -> u8 {
    let bpr: u64;
    unsafe {
        asm!(
            "mrs {0}, icc_bpr1_el1",
            out(reg) bpr,
        );
    }
    bpr as u8
}

pub fn set_binary_point(bpr: u8) {
    unsafe {
        asm!(
            "msr icc_bpr1_el1, {0}",
            in(reg) bpr as u64,
        );
    }
}
