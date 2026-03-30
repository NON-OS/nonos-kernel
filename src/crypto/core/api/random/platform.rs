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

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) static KEYGEN_COUNTER: AtomicU64 = AtomicU64::new(0xB5A1_9E37_C4D2_8F6B);

#[inline]
pub(super) fn rdrand64_or_tsc() -> u64 {
    for _ in 0..10 { let mut val: u64 = 0; let success: u8; unsafe { core::arch::asm!("rdrand {0}", "setc {1}", out(reg) val, out(reg_byte) success, options(nostack)); } if success != 0 && val != 0 { return val; } }
    let tsc = read_tsc(); let pit = read_pit_counter() as u64; let ctr = KEYGEN_COUNTER.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    tsc ^ ctr ^ (pit << 32) ^ (pit << 16)
}

#[cfg(target_arch = "x86_64")]
#[inline] pub(super) fn read_tsc() -> u64 { unsafe { let lo: u32; let hi: u32; core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); (lo as u64) | ((hi as u64) << 32) } }
#[cfg(not(target_arch = "x86_64"))]
#[inline] pub(super) fn read_tsc() -> u64 { 0 }

#[cfg(target_arch = "x86_64")]
#[inline] pub(super) fn get_stack_pointer() -> u64 { let rsp: u64; unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack)); } rsp }
#[cfg(not(target_arch = "x86_64"))]
#[inline] pub(super) fn get_stack_pointer() -> u64 { 0 }

#[cfg(target_arch = "x86_64")]
pub(super) fn read_pit_counter() -> u16 {
    const PIT_CHANNEL0: u16 = 0x40; const PIT_COMMAND: u16 = 0x43; const LATCH_CHANNEL0: u8 = 0x00;
    unsafe {
        core::arch::asm!("out dx, al", in("dx") PIT_COMMAND, in("al") LATCH_CHANNEL0, options(nostack, preserves_flags, nomem));
        let low: u8; core::arch::asm!("in al, dx", out("al") low, in("dx") PIT_CHANNEL0, options(nostack, preserves_flags, nomem));
        let high: u8; core::arch::asm!("in al, dx", out("al") high, in("dx") PIT_CHANNEL0, options(nostack, preserves_flags, nomem));
        ((high as u16) << 8) | (low as u16)
    }
}
#[cfg(not(target_arch = "x86_64"))]
pub(super) fn read_pit_counter() -> u16 { 0 }

pub(super) fn read_rtc_timestamp() -> u64 { crate::arch::x86_64::time::rtc::read_unix_timestamp() }
