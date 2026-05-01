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

pub fn cpu_id() -> usize {
    hart_id()
}

pub fn hart_id() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) id, options(nostack));
    }
    id
}

pub fn mvendorid() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, mvendorid", out(reg) id, options(nostack));
    }
    id
}

pub fn marchid() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, marchid", out(reg) id, options(nostack));
    }
    id
}

pub fn mimpid() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, mimpid", out(reg) id, options(nostack));
    }
    id
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
        Self {
            hart_id: hart_id(),
            mvendorid: mvendorid(),
            marchid: marchid(),
            mimpid: mimpid(),
        }
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
