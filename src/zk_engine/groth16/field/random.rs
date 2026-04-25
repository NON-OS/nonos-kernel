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

use super::constants::BN254_MODULUS;
use super::types::FieldElement;

impl FieldElement {
    pub fn random() -> FieldElement {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let tsc1: u64;
            let tsc2: u64;
            let rdseed_val: u64;
            let rdrand_val: u64;
            unsafe {
                core::arch::asm!("rdtsc", out("rax") tsc1);
                for _ in 0..((i + 1) * 7) {
                    core::hint::spin_loop();
                }
                core::arch::asm!("rdtsc", out("rax") tsc2);
                let mut val: u64 = 0;
                let success: u8;
                core::arch::asm!("rdseed {0}", "setc {1}", out(reg) val, out(reg_byte) success, options(nomem, nostack));
                rdseed_val = if success != 0 { val } else { tsc1.wrapping_mul(0x5851F42D4C957F2D) };
                let mut rval: u64 = 0;
                let rsuccess: u8;
                core::arch::asm!("rdrand {0}", "setc {1}", out(reg) rval, out(reg_byte) rsuccess, options(nomem, nostack));
                rdrand_val =
                    if rsuccess != 0 { rval } else { tsc2.wrapping_mul(0xC6A4A7935BD1E995) };
            }
            let mixed = tsc1.wrapping_add(tsc2.rotate_left(17)).wrapping_mul(0x9E3779B97F4A7C15)
                ^ rdseed_val
                ^ rdrand_val.rotate_right(23);
            limbs[i] = mixed;
        }
        while Self::gte(&limbs, &BN254_MODULUS) {
            Self::sub_assign(&mut limbs, &BN254_MODULUS);
        }
        FieldElement { limbs }.to_montgomery()
    }
}
