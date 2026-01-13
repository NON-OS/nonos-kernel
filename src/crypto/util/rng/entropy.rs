// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::Ordering;
use super::GLOBAL_COUNTER;

#[cfg(target_arch = "x86_64")]
pub fn try_rdrand64() -> Option<u64> {
    // # SAFETY: RDRAND is a valid x86_64 instruction that reads from hardware RNG.
    // # The instruction sets CF=1 on success, CF=0 on failure.
    unsafe {
        let mut val: u64;
        let mut success: u8;
        core::arch::asm!(
            "rdrand {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        if success != 0 { Some(val) } else { None }
    }
}

#[cfg(target_arch = "x86_64")]
pub fn try_rdseed64() -> Option<u64> {
    // # SAFETY: RDSEED is a valid x86_64 instruction that reads true hardware entropy.
    // # The instruction sets CF=1 on success, CF=0 on failure.
    unsafe {
        let mut val: u64;
        let mut success: u8;
        core::arch::asm!(
            "rdseed {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        if success != 0 { Some(val) } else { None }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdrand64() -> Option<u64> { None }

#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdseed64() -> Option<u64> { None }
pub fn get_entropy64() -> u64 {
    if let Some(v) = try_rdseed64() {
        return v;
    }

    if let Some(v) = try_rdrand64() {
        return v;
    }

    let mut e = GLOBAL_COUNTER.fetch_add(1, Ordering::SeqCst);

    #[cfg(target_arch = "x86_64")]
    {
        // # SAFETY: RDTSC is a valid x86_64 instruction that reads the timestamp counter.
        unsafe {
            let mut lo: u32 = 0;
            let mut hi: u32 = 0;
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
            e ^= (lo as u64) | ((hi as u64) << 32);
        }
    }

    let addr = &e as *const u64 as u64;
    e ^= addr;
    e
}

pub fn get_tsc_entropy() -> u64 {
    let mut e = GLOBAL_COUNTER.fetch_add(1, Ordering::SeqCst);

    #[cfg(target_arch = "x86_64")]
    {
        // # SAFETY: RDTSC is a valid x86_64 instruction that reads the timestamp counter.
        unsafe {
            let mut lo: u32 = 0;
            let mut hi: u32 = 0;
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
            e ^= (lo as u64) | ((hi as u64) << 32);
        }
    }

    let addr = &e as *const u64 as u64;
    e ^= addr;
    e
}

pub fn collect_seed_entropy() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let mut offset = 0;

    for _ in 0..4 {
        if let Some(v) = try_rdseed64() {
            if offset + 8 <= 32 {
                seed[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
                offset += 8;
            }
        }
    }

    while offset < 32 {
        if let Some(v) = try_rdrand64() {
            let remaining = 32 - offset;
            let copy_len = core::cmp::min(8, remaining);
            seed[offset..offset + copy_len].copy_from_slice(&v.to_le_bytes()[..copy_len]);
            offset += copy_len;
        } else {
            break;
        }
    }

    while offset < 32 {
        let v = get_entropy64();
        let remaining = 32 - offset;
        let copy_len = core::cmp::min(8, remaining);
        seed[offset..offset + copy_len].copy_from_slice(&v.to_le_bytes()[..copy_len]);
        offset += copy_len;
    }

    seed
}
