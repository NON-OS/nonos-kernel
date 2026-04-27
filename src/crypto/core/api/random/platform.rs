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

use core::sync::atomic::AtomicU64;

pub(super) static KEYGEN_COUNTER: AtomicU64 = AtomicU64::new(0xB5A1_9E37_C4D2_8F6B);

/* DEV NOTES eK@nonos.systems
   Provides random value with fallback to TSC-based PRNG when hardware entropy unavailable.
   The TSC mixing provides reasonable entropy for keygen counters but callers requiring
   cryptographic randomness should validate hardware entropy availability first.
*/
#[inline]
pub(super) fn rdrand64_or_tsc() -> u64 {
    secure_random64().unwrap_or_else(|| {
        let tsc = read_tsc();
        let counter = KEYGEN_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        tsc.wrapping_mul(0x5851f42d4c957f2d) ^ counter
    })
}

pub(super) fn secure_random64() -> Option<u64> {
    if let Some(val) = try_rdrand64() {
        return Some(val);
    }
    if let Some(val) = try_rdseed64() {
        return Some(val);
    }
    if let Some(val) = try_virtio_rng64() {
        return Some(val);
    }
    None
}

fn try_rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let mut val: u64 = 0;
        let success: u8;
        unsafe {
            core::arch::asm!("rdrand {0}", "setc {1}", out(reg) val, out(reg_byte) success, options(nostack));
        }
        if success != 0 && val != 0 {
            return Some(val);
        }
    }
    None
}

fn try_rdseed64() -> Option<u64> {
    for _ in 0..10 {
        let mut val: u64;
        let success: u8;
        unsafe {
            core::arch::asm!("rdseed {0}", "setc {1}", out(reg) val, out(reg_byte) success, options(nostack));
        }
        if success != 0 {
            return Some(val);
        }
    }
    None
}

fn try_virtio_rng64() -> Option<u64> {
    let mut buf = [0u8; 8];
    crate::drivers::virtio_rng::fill_random(&mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn read_tsc() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        (lo as u64) | ((hi as u64) << 32)
    }
}
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(super) fn read_tsc() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn get_stack_pointer() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
    }
    rsp
}
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(super) fn get_stack_pointer() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
pub(super) fn read_pit_counter() -> u16 {
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_COMMAND: u16 = 0x43;
    const LATCH_CHANNEL0: u8 = 0x00;
    unsafe {
        core::arch::asm!("out dx, al", in("dx") PIT_COMMAND, in("al") LATCH_CHANNEL0, options(nostack, preserves_flags, nomem));
        let low: u8;
        core::arch::asm!("in al, dx", out("al") low, in("dx") PIT_CHANNEL0, options(nostack, preserves_flags, nomem));
        let high: u8;
        core::arch::asm!("in al, dx", out("al") high, in("dx") PIT_CHANNEL0, options(nostack, preserves_flags, nomem));
        ((high as u16) << 8) | (low as u16)
    }
}
#[cfg(not(target_arch = "x86_64"))]
pub(super) fn read_pit_counter() -> u16 {
    0
}

pub(super) fn read_rtc_timestamp() -> u64 {
    crate::arch::x86_64::time::rtc::read_unix_timestamp()
}
