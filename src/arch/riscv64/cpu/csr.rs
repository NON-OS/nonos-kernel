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

pub const SSTATUS: usize = 0x100;
pub const SIE: usize = 0x104;
pub const STVEC: usize = 0x105;
pub const SCOUNTEREN: usize = 0x106;
pub const SSCRATCH: usize = 0x140;
pub const SEPC: usize = 0x141;
pub const SCAUSE: usize = 0x142;
pub const STVAL: usize = 0x143;
pub const SIP: usize = 0x144;
pub const SATP: usize = 0x180;

pub const MSTATUS: usize = 0x300;
pub const MISA: usize = 0x301;
pub const MIE: usize = 0x304;
pub const MTVEC: usize = 0x305;
pub const MSCRATCH: usize = 0x340;
pub const MEPC: usize = 0x341;
pub const MCAUSE: usize = 0x342;
pub const MTVAL: usize = 0x343;
pub const MIP: usize = 0x344;

pub const MVENDORID: usize = 0xF11;
pub const MARCHID: usize = 0xF12;
pub const MIMPID: usize = 0xF13;
pub const MHARTID: usize = 0xF14;

pub const TIME: usize = 0xC01;
pub const CYCLE: usize = 0xC00;
pub const INSTRET: usize = 0xC02;

pub const SSTATUS_SIE: usize = 1 << 1;
pub const SSTATUS_SPIE: usize = 1 << 5;
pub const SSTATUS_SPP: usize = 1 << 8;
// FS[14:13] and VS[10:9] track FP / vector extension state per
// privileged spec. Off=0, Initial=1, Clean=2, Dirty=3. Boot leaves
// both at Off; lazy-enable happens on first user FP/V instruction.
pub const SSTATUS_FS_SHIFT: usize = 13;
pub const SSTATUS_FS_MASK: usize = 0b11 << SSTATUS_FS_SHIFT;
pub const SSTATUS_FS_OFF: usize = 0 << SSTATUS_FS_SHIFT;
pub const SSTATUS_FS_INITIAL: usize = 1 << SSTATUS_FS_SHIFT;
pub const SSTATUS_FS_CLEAN: usize = 2 << SSTATUS_FS_SHIFT;
pub const SSTATUS_FS_DIRTY: usize = 3 << SSTATUS_FS_SHIFT;
pub const SSTATUS_VS_SHIFT: usize = 9;
pub const SSTATUS_VS_MASK: usize = 0b11 << SSTATUS_VS_SHIFT;
pub const SSTATUS_VS_OFF: usize = 0 << SSTATUS_VS_SHIFT;
pub const SSTATUS_VS_INITIAL: usize = 1 << SSTATUS_VS_SHIFT;
pub const SSTATUS_VS_CLEAN: usize = 2 << SSTATUS_VS_SHIFT;
pub const SSTATUS_VS_DIRTY: usize = 3 << SSTATUS_VS_SHIFT;
pub const SSTATUS_SUM: usize = 1 << 18;
pub const SSTATUS_MXR: usize = 1 << 19;

pub const SIE_SSIE: usize = 1 << 1;
pub const SIE_STIE: usize = 1 << 5;
pub const SIE_SEIE: usize = 1 << 9;

pub const SIP_SSIP: usize = 1 << 1;
pub const SIP_STIP: usize = 1 << 5;
pub const SIP_SEIP: usize = 1 << 9;

#[inline]
pub fn read_csr(csr: usize) -> usize {
    let value: usize;
    match csr {
        SSTATUS => unsafe { asm!("csrr {}, sstatus", out(reg) value, options(nostack)) },
        SIE => unsafe { asm!("csrr {}, sie", out(reg) value, options(nostack)) },
        STVEC => unsafe { asm!("csrr {}, stvec", out(reg) value, options(nostack)) },
        SSCRATCH => unsafe { asm!("csrr {}, sscratch", out(reg) value, options(nostack)) },
        SEPC => unsafe { asm!("csrr {}, sepc", out(reg) value, options(nostack)) },
        SCAUSE => unsafe { asm!("csrr {}, scause", out(reg) value, options(nostack)) },
        STVAL => unsafe { asm!("csrr {}, stval", out(reg) value, options(nostack)) },
        SIP => unsafe { asm!("csrr {}, sip", out(reg) value, options(nostack)) },
        SATP => unsafe { asm!("csrr {}, satp", out(reg) value, options(nostack)) },
        TIME => unsafe { asm!("csrr {}, time", out(reg) value, options(nostack)) },
        CYCLE => unsafe { asm!("csrr {}, cycle", out(reg) value, options(nostack)) },
        _ => return 0,
    }
    value
}

#[inline]
pub fn write_csr(csr: usize, value: usize) {
    match csr {
        SSTATUS => unsafe { asm!("csrw sstatus, {}", in(reg) value, options(nostack)) },
        SIE => unsafe { asm!("csrw sie, {}", in(reg) value, options(nostack)) },
        STVEC => unsafe { asm!("csrw stvec, {}", in(reg) value, options(nostack)) },
        SSCRATCH => unsafe { asm!("csrw sscratch, {}", in(reg) value, options(nostack)) },
        SEPC => unsafe { asm!("csrw sepc, {}", in(reg) value, options(nostack)) },
        SCAUSE => unsafe { asm!("csrw scause, {}", in(reg) value, options(nostack)) },
        STVAL => unsafe { asm!("csrw stval, {}", in(reg) value, options(nostack)) },
        SIP => unsafe { asm!("csrw sip, {}", in(reg) value, options(nostack)) },
        SATP => unsafe { asm!("csrw satp, {}", in(reg) value, options(nostack)) },
        _ => {}
    }
}

#[inline]
pub fn set_csr(csr: usize, bits: usize) {
    match csr {
        SSTATUS => unsafe { asm!("csrs sstatus, {}", in(reg) bits, options(nostack)) },
        SIE => unsafe { asm!("csrs sie, {}", in(reg) bits, options(nostack)) },
        SIP => unsafe { asm!("csrs sip, {}", in(reg) bits, options(nostack)) },
        _ => {}
    }
}

#[inline]
pub fn clear_csr(csr: usize, bits: usize) {
    match csr {
        SSTATUS => unsafe { asm!("csrc sstatus, {}", in(reg) bits, options(nostack)) },
        SIE => unsafe { asm!("csrc sie, {}", in(reg) bits, options(nostack)) },
        SIP => unsafe { asm!("csrc sip, {}", in(reg) bits, options(nostack)) },
        _ => {}
    }
}

pub fn read_sstatus() -> usize {
    read_csr(SSTATUS)
}

pub fn read_sepc() -> usize {
    read_csr(SEPC)
}

pub fn read_scause() -> usize {
    read_csr(SCAUSE)
}

pub fn read_stval() -> usize {
    read_csr(STVAL)
}

pub fn read_time() -> u64 {
    read_csr(TIME) as u64
}

pub fn read_cycle() -> u64 {
    read_csr(CYCLE) as u64
}
