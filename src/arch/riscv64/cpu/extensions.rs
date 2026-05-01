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

pub fn has_extension(ext: Extension) -> bool {
    let misa = read_misa();

    if ext == Extension::G {
        return has_extension(Extension::I)
            && has_extension(Extension::M)
            && has_extension(Extension::A)
            && has_extension(Extension::F)
            && has_extension(Extension::D);
    }

    match ext.bit() {
        Some(bit) => (misa >> bit) & 1 != 0,
        None => false,
    }
}

fn read_misa() -> usize {
    let misa: usize;
    unsafe {
        asm!("csrr {}, misa", out(reg) misa, options(nostack));
    }
    misa
}

pub fn mxl() -> usize {
    let misa = read_misa();
    (misa >> 62) & 0x3
}

pub fn is_rv64() -> bool {
    mxl() == 2
}

pub fn is_rv32() -> bool {
    mxl() == 1
}

pub fn extensions_string() -> alloc::string::String {
    let mut s = alloc::string::String::new();

    let exts = [
        (Extension::I, 'I'),
        (Extension::M, 'M'),
        (Extension::A, 'A'),
        (Extension::F, 'F'),
        (Extension::D, 'D'),
        (Extension::C, 'C'),
        (Extension::V, 'V'),
        (Extension::H, 'H'),
        (Extension::S, 'S'),
        (Extension::U, 'U'),
    ];

    for (ext, c) in exts {
        if has_extension(ext) {
            s.push(c);
        }
    }

    s
}

pub fn has_supervisor_mode() -> bool {
    has_extension(Extension::S)
}

pub fn has_user_mode() -> bool {
    has_extension(Extension::U)
}

pub fn has_hypervisor() -> bool {
    has_extension(Extension::H)
}

pub fn has_vector() -> bool {
    has_extension(Extension::V)
}

pub fn has_compressed() -> bool {
    has_extension(Extension::C)
}

pub fn has_atomics() -> bool {
    has_extension(Extension::A)
}

pub fn has_float() -> bool {
    has_extension(Extension::F)
}

pub fn has_double() -> bool {
    has_extension(Extension::D)
}
