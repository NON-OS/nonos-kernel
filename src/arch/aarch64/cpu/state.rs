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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    El0,
    El1,
    El2,
    El3,
}

pub fn current_el() -> ExceptionLevel {
    let el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) el, options(nostack));
    }

    match (el >> 2) & 0x3 {
        0 => ExceptionLevel::El0,
        1 => ExceptionLevel::El1,
        2 => ExceptionLevel::El2,
        3 => ExceptionLevel::El3,
        _ => unreachable!(),
    }
}

pub fn is_el1() -> bool {
    current_el() == ExceptionLevel::El1
}

pub fn is_el2() -> bool {
    current_el() == ExceptionLevel::El2
}

pub fn is_el3() -> bool {
    current_el() == ExceptionLevel::El3
}

pub fn read_sp() -> u64 {
    let sp: u64;
    unsafe {
        asm!("mov {}, sp", out(reg) sp, options(nostack));
    }
    sp
}

pub fn read_lr() -> u64 {
    let lr: u64;
    unsafe {
        asm!("mov {}, lr", out(reg) lr, options(nostack));
    }
    lr
}

pub fn read_pc() -> u64 {
    let pc: u64;
    unsafe {
        asm!("adr {}, .", out(reg) pc, options(nostack));
    }
    pc
}

pub fn read_spsr_el1() -> u64 {
    let spsr: u64;
    unsafe {
        asm!("mrs {}, spsr_el1", out(reg) spsr, options(nostack));
    }
    spsr
}

pub fn read_elr_el1() -> u64 {
    let elr: u64;
    unsafe {
        asm!("mrs {}, elr_el1", out(reg) elr, options(nostack));
    }
    elr
}

pub fn read_esr_el1() -> u64 {
    let esr: u64;
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nostack));
    }
    esr
}

pub fn read_far_el1() -> u64 {
    let far: u64;
    unsafe {
        asm!("mrs {}, far_el1", out(reg) far, options(nostack));
    }
    far
}

pub fn read_daif() -> u64 {
    let daif: u64;
    unsafe {
        asm!("mrs {}, daif", out(reg) daif, options(nostack));
    }
    daif
}

pub fn read_nzcv() -> u64 {
    let nzcv: u64;
    unsafe {
        asm!("mrs {}, nzcv", out(reg) nzcv, options(nostack));
    }
    nzcv
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuState {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl CpuState {
    pub fn capture() -> Self {
        let mut state = Self::default();

        state.sp = read_sp();
        state.pc = read_pc();
        state.pstate = read_spsr_el1();

        state
    }
}
