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
pub enum CpuFeature {
    Fp,
    Asimd,
    Aes,
    Pmull,
    Sha1,
    Sha256,
    Crc32,
    Atomics,
    Rdm,
    Sha3,
    Sm3,
    Sm4,
    Dp,
    Fhm,
    Ts,
    Flagm,
    Ssbs,
    Sb,
    Pauth,
    Dcpop,
    Dcpodp,
    Sve,
    Sve2,
    Sme,
    Bti,
    Mte,
    Rng,
}

pub fn has_feature(feature: CpuFeature) -> bool {
    let aa64isar0 = read_aa64isar0();
    let aa64isar1 = read_aa64isar1();
    let aa64pfr0 = read_aa64pfr0();
    let aa64pfr1 = read_aa64pfr1();
    let aa64mmfr2 = read_aa64mmfr2();

    match feature {
        CpuFeature::Fp => (aa64pfr0 & 0xF) != 0xF,
        CpuFeature::Asimd => ((aa64pfr0 >> 4) & 0xF) != 0xF,
        CpuFeature::Aes => ((aa64isar0 >> 4) & 0xF) >= 1,
        CpuFeature::Pmull => ((aa64isar0 >> 4) & 0xF) >= 2,
        CpuFeature::Sha1 => ((aa64isar0 >> 8) & 0xF) >= 1,
        CpuFeature::Sha256 => ((aa64isar0 >> 12) & 0xF) >= 1,
        CpuFeature::Crc32 => ((aa64isar0 >> 16) & 0xF) >= 1,
        CpuFeature::Atomics => ((aa64isar0 >> 20) & 0xF) >= 2,
        CpuFeature::Rdm => ((aa64isar0 >> 28) & 0xF) >= 1,
        CpuFeature::Sha3 => ((aa64isar0 >> 32) & 0xF) >= 1,
        CpuFeature::Sm3 => ((aa64isar0 >> 36) & 0xF) >= 1,
        CpuFeature::Sm4 => ((aa64isar0 >> 40) & 0xF) >= 1,
        CpuFeature::Dp => ((aa64isar0 >> 44) & 0xF) >= 1,
        CpuFeature::Fhm => ((aa64isar0 >> 48) & 0xF) >= 1,
        CpuFeature::Ts => ((aa64isar0 >> 52) & 0xF) >= 1,
        CpuFeature::Flagm => ((aa64isar0 >> 52) & 0xF) >= 2,
        CpuFeature::Ssbs => ((aa64pfr1 >> 4) & 0xF) >= 1,
        CpuFeature::Sb => ((aa64isar1 >> 36) & 0xF) >= 1,
        CpuFeature::Pauth => ((aa64isar1 >> 4) & 0xF) >= 1,
        CpuFeature::Dcpop => ((aa64isar1 >> 0) & 0xF) >= 1,
        CpuFeature::Dcpodp => ((aa64isar1 >> 0) & 0xF) >= 2,
        CpuFeature::Sve => ((aa64pfr0 >> 32) & 0xF) >= 1,
        CpuFeature::Sve2 => false,
        CpuFeature::Sme => ((aa64pfr1 >> 24) & 0xF) >= 1,
        CpuFeature::Bti => ((aa64pfr1 >> 0) & 0xF) >= 1,
        CpuFeature::Mte => ((aa64pfr1 >> 8) & 0xF) >= 1,
        CpuFeature::Rng => ((aa64isar0 >> 60) & 0xF) >= 1,
    }
}

fn read_aa64isar0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, id_aa64isar0_el1", out(reg) value, options(nostack));
    }
    value
}

fn read_aa64isar1() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, id_aa64isar1_el1", out(reg) value, options(nostack));
    }
    value
}

fn read_aa64pfr0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) value, options(nostack));
    }
    value
}

fn read_aa64pfr1() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) value, options(nostack));
    }
    value
}

fn read_aa64mmfr2() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, id_aa64mmfr2_el1", out(reg) value, options(nostack));
    }
    value
}

pub fn print_features() {
    let features = [
        (CpuFeature::Fp, "FP"),
        (CpuFeature::Asimd, "ASIMD"),
        (CpuFeature::Aes, "AES"),
        (CpuFeature::Sha256, "SHA256"),
        (CpuFeature::Atomics, "ATOMICS"),
        (CpuFeature::Sve, "SVE"),
        (CpuFeature::Mte, "MTE"),
    ];

    for (feature, name) in features {
        if has_feature(feature) {
            crate::sys::serial::print(name.as_bytes());
            crate::sys::serial::print(b" ");
        }
    }
    crate::sys::serial::println(b"");
}
