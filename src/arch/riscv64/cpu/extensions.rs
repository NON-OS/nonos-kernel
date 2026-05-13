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
pub enum Extension {
    I,
    M,
    A,
    F,
    D,
    G,
    Q,
    C,
    B,
    V,
    H,
    S,
    U,
    Zicsr,
    Zifencei,
    Zicntr,
    Zihpm,
    Zkr,
    Zkn,
    Zks,
    Zvl128b,
    Zvl256b,
}

impl Extension {
    fn bit(&self) -> Option<usize> {
        match self {
            Extension::I => Some(8),
            Extension::M => Some(12),
            Extension::A => Some(0),
            Extension::F => Some(5),
            Extension::D => Some(3),
            Extension::G => None,
            Extension::Q => Some(16),
            Extension::C => Some(2),
            Extension::B => Some(1),
            Extension::V => Some(21),
            Extension::H => Some(7),
            Extension::S => Some(18),
            Extension::U => Some(20),
            _ => None,
        }
    }
}

// LIMIT: `misa` is an M-mode CSR; reading it from S-mode raises an
// illegal-instruction exception under any firmware-managed kernel.
// This helper exists for M-mode callers only. S-mode code paths must
// go through `super::caps` (populated from DTB `riscv,isa`).
pub unsafe fn has_extension_from_misa(ext: Extension) -> bool {
    let misa = unsafe { read_misa() };
    if ext == Extension::G {
        return unsafe {
            has_extension_from_misa(Extension::I)
                && has_extension_from_misa(Extension::M)
                && has_extension_from_misa(Extension::A)
                && has_extension_from_misa(Extension::F)
                && has_extension_from_misa(Extension::D)
        };
    }
    match ext.bit() {
        Some(bit) => (misa >> bit) & 1 != 0,
        None => false,
    }
}

unsafe fn read_misa() -> usize {
    let misa: usize;
    asm!("csrr {}, misa", out(reg) misa, options(nostack));
    misa
}

pub unsafe fn mxl() -> usize {
    let misa = unsafe { read_misa() };
    (misa >> 62) & 0x3
}

pub unsafe fn is_rv64() -> bool {
    unsafe { mxl() == 2 }
}

pub unsafe fn is_rv32() -> bool {
    unsafe { mxl() == 1 }
}

// S-mode-safe queries. Read from the DTB-populated capability store
// configured once on BSP; APs see the same value. No CSR access.

pub fn has_vector() -> bool {
    super::caps::has_v()
}

pub fn has_compressed() -> bool {
    super::caps::has_c()
}

pub fn has_atomics() -> bool {
    super::caps::has_a()
}

pub fn has_float() -> bool {
    super::caps::has_f()
}

pub fn has_double() -> bool {
    super::caps::has_d()
}
