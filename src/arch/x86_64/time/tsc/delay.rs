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

use core::sync::atomic::Ordering;
use super::asm::rdtsc_unserialized;
use super::conversion::ns_to_ticks;
use super::state::CALIBRATED;

pub fn delay_ns(ns: u64) {
    if !CALIBRATED.load(Ordering::Relaxed) {
        for _ in 0..ns / 10 {
            core::hint::spin_loop();
        }
        return;
    }

    let target_ticks = ns_to_ticks(ns);
    let start = rdtsc_unserialized();
    let end = start.wrapping_add(target_ticks);

    while rdtsc_unserialized() < end {
        core::hint::spin_loop();
    }
}

pub fn delay_us(us: u64) {
    delay_ns(us * 1000);
}

pub fn delay_ms(ms: u64) {
    delay_ns(ms * 1_000_000);
}

pub fn delay_precise_ns(ns: u64) {
    if !CALIBRATED.load(Ordering::Relaxed) {
        delay_ns(ns);
        return;
    }

    let target_ticks = ns_to_ticks(ns);
    let start = rdtsc_unserialized();
    let end = start.wrapping_add(target_ticks);

    while rdtsc_unserialized() < end {
        // SAFETY: PAUSE is a safe, unprivileged x86 instruction.
        unsafe {
            core::arch::asm!("pause", options(nostack, preserves_flags, nomem));
        }
    }
}
