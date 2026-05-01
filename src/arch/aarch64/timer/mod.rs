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

pub mod generic;
pub mod physical;
pub mod virtual_timer;

pub use generic::{frequency, current_count, nanoseconds_to_ticks, ticks_to_nanoseconds};
pub use physical::{PhysicalTimer, set_physical_timer};
pub use virtual_timer::{VirtualTimer, set_virtual_timer};

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static TIMER_FREQ: AtomicU64 = AtomicU64::new(0);

pub fn init_timer() {
    let freq = read_frequency();
    TIMER_FREQ.store(freq, Ordering::Release);

    enable_timer();
    set_timer(10_000_000);
}

pub fn init_timer_cpu() {
    enable_timer();
}

fn read_frequency() -> u64 {
    let freq: u64;
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) freq);
    }
    freq
}

fn enable_timer() {
    unsafe {
        asm!(
            "mrs x0, cntkctl_el1",
            "orr x0, x0, #3",
            "msr cntkctl_el1, x0",
            out("x0") _,
        );
    }
}

pub fn current_time_ns() -> u64 {
    let count = current_count();
    let freq = TIMER_FREQ.load(Ordering::Acquire);

    if freq == 0 {
        return 0;
    }

    (count * 1_000_000_000) / freq
}

pub fn current_time_us() -> u64 {
    let count = current_count();
    let freq = TIMER_FREQ.load(Ordering::Acquire);

    if freq == 0 {
        return 0;
    }

    (count * 1_000_000) / freq
}

pub fn set_timer(ns: u64) {
    let freq = TIMER_FREQ.load(Ordering::Acquire);
    let ticks = (ns * freq) / 1_000_000_000;

    let cval: u64;
    unsafe {
        asm!("mrs {}, cntpct_el0", out(reg) cval);
    }

    let next = cval + ticks;

    unsafe {
        asm!("msr cntp_cval_el0, {}", in(reg) next);
        asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }
}

pub fn disable_timer() {
    unsafe {
        asm!("msr cntp_ctl_el0, {}", in(reg) 0u64);
    }
}

pub fn handle_timer_interrupt() {
    set_timer(10_000_000);
}

pub fn delay_ns(ns: u64) {
    let start = current_time_ns();
    while current_time_ns() - start < ns {
        core::hint::spin_loop();
    }
}

pub fn delay_us(us: u64) {
    delay_ns(us * 1000);
}

pub fn delay_ms(ms: u64) {
    delay_ns(ms * 1_000_000);
}
