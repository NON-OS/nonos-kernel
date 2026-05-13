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

use crate::arch::riscv64::sbi::base as sbi_base;

pub fn cpu_id() -> usize {
    hart_id()
}

// start.S sets tp = hartid on both BSP and AP entry; tp survives the
// call chain by ABI. Reading tp here is a pure register move and is
// safe in S-mode (unlike mhartid, which faults).
pub fn hart_id() -> usize {
    let id: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) id, options(nomem, nostack, preserves_flags));
    }
    id
}

// SBI Base extension proxies for what would otherwise be M-only CSRs.
// Implementations that lack the extension return 0.
pub fn mvendorid() -> usize {
    sbi_base::mvendorid().unwrap_or(0)
}

pub fn marchid() -> usize {
    sbi_base::marchid().unwrap_or(0)
}

pub fn mimpid() -> usize {
    sbi_base::mimpid().unwrap_or(0)
}

pub fn mconfigptr() -> usize {
    0
}

#[derive(Debug, Clone, Copy)]
pub struct HartInfo {
    pub hart_id: usize,
    pub mvendorid: usize,
    pub marchid: usize,
    pub mimpid: usize,
}

impl HartInfo {
    pub fn current() -> Self {
        Self { hart_id: hart_id(), mvendorid: mvendorid(), marchid: marchid(), mimpid: mimpid() }
    }

    pub fn vendor_name(&self) -> &'static str {
        match self.mvendorid {
            0x489 => "SiFive",
            0x5B7 => "Andes",
            0x61F => "T-Head",
            0x710 => "StarFive",
            _ => "Unknown",
        }
    }
}

pub fn is_primary_hart() -> bool {
    hart_id() == 0
}

pub fn print_hart_info() {
    let info = HartInfo::current();

    crate::sys::serial::print(b"RISC-V Hart ");
    crate::sys::serial::print_dec(info.hart_id as u64);
    crate::sys::serial::print(b": ");
    crate::sys::serial::print(info.vendor_name().as_bytes());
    crate::sys::serial::println(b"");
}
