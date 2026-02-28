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

use super::time::now_ns;
use super::tsc::{rdtsc, ns_to_tsc};

pub fn sleep_long_ns<F>(ns: u64, callback: F)
where
    F: Fn(),
{
    let start = now_ns();
    let end_time = start + ns;
    while now_ns() < end_time {
        callback();
        let remaining_ns = end_time.saturating_sub(now_ns());
        if remaining_ns > 10_000_000 {
            x86_64::instructions::interrupts::enable();
            x86_64::instructions::hlt();
            x86_64::instructions::interrupts::disable();
        } else if remaining_ns > 1000 {
            for _ in 0..(remaining_ns / 100) {
                unsafe { core::arch::asm!("pause"); }
            }
        } else {
            unsafe { core::arch::asm!("nop"); }
        }
    }
}

pub fn busy_sleep_ns(ns: u64) {
    let start = now_ns();
    while now_ns() - start < ns {
        unsafe {
            core::arch::asm!("pause");
        }
    }
}

pub fn delay_precise_ns(nanoseconds: u64) {
    let start_tsc = rdtsc();
    let target_ticks = ns_to_tsc(nanoseconds);
    let end_tsc = start_tsc + target_ticks;
    while rdtsc() < end_tsc {
        unsafe {
            core::arch::asm!("pause");
        }
    }
}

pub fn delay_us(microseconds: u64) {
    delay_precise_ns(microseconds * 1000)
}

pub fn delay_ms(milliseconds: u64) {
    delay_precise_ns(milliseconds * 1_000_000)
}
