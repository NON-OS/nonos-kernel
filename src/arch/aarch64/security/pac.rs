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

pub fn init_pac() {
    if !has_feature(CpuFeature::Pauth) {
        return;
    }

    generate_keys();
    enable_pac();
}

fn generate_keys() {
    let key_a = generate_random_key();
    let key_b = generate_random_key();
    let key_da = generate_random_key();
    let key_db = generate_random_key();
    let key_ga = generate_random_key();

    unsafe {
        asm!("msr apiakeylo_el1, {}", in(reg) key_a.0);
        asm!("msr apiakeyhi_el1, {}", in(reg) key_a.1);
        asm!("msr apibkeylo_el1, {}", in(reg) key_b.0);
        asm!("msr apibkeyhi_el1, {}", in(reg) key_b.1);
        asm!("msr apdakeylo_el1, {}", in(reg) key_da.0);
        asm!("msr apdakeyhi_el1, {}", in(reg) key_da.1);
        asm!("msr apdbkeylo_el1, {}", in(reg) key_db.0);
        asm!("msr apdbkeyhi_el1, {}", in(reg) key_db.1);
        asm!("msr apgakeylo_el1, {}", in(reg) key_ga.0);
        asm!("msr apgakeyhi_el1, {}", in(reg) key_ga.1);
        asm!("isb");
    }
}

fn generate_random_key() -> (u64, u64) {
    if has_feature(CpuFeature::Rng) {
        let mut lo: u64;
        let mut hi: u64;

        unsafe {
            asm!("mrs {}, rndr", out(reg) lo);
            asm!("mrs {}, rndr", out(reg) hi);
        }

        (lo, hi)
    } else {
        let count = super::super::timer::current_count();
        (count.wrapping_mul(0x5851_F42D_4C95_7F2D), count.wrapping_mul(0x14057_B7E_F767_814F))
    }
}

pub fn enable_pac() {
    if !has_feature(CpuFeature::Pauth) {
        return;
    }

    unsafe {
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        sctlr |= 1 << 31;
        sctlr |= 1 << 27;

        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr
        );
    }
}

pub fn disable_pac() {
    unsafe {
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        sctlr &= !(1 << 31);
        sctlr &= !(1 << 27);

        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr
        );
    }
}

pub fn pac_enabled() -> bool {
    if !has_feature(CpuFeature::Pauth) {
        return false;
    }

    let sctlr: u64;
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);
    }

    (sctlr & (1 << 31)) != 0 || (sctlr & (1 << 27)) != 0
}

pub fn sign_return_address(lr: u64, sp: u64) -> u64 {
    let signed: u64;
    unsafe {
        asm!(
            "paciasp",
            in("lr") lr,
            in("sp") sp,
            lateout("lr") signed
        );
    }
    signed
}

pub fn authenticate_return_address(lr: u64, sp: u64) -> u64 {
    let authenticated: u64;
    unsafe {
        asm!(
            "autiasp",
            in("lr") lr,
            in("sp") sp,
            lateout("lr") authenticated
        );
    }
    authenticated
}
