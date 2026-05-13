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

pub mod clint;

pub use clint::{clear_timer_interrupt, set_timer_interrupt, Clint};

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

// Sane QEMU virt fallback when the DTB walker hasn't run yet.
// `set_frequency` overrides this once /cpus/timebase-frequency is parsed.
static TIMER_FREQ: AtomicU64 = AtomicU64::new(10_000_000);

// Called from the DTB adapter with the parsed timebase. Idempotent.
pub fn set_frequency(hz: u64) {
    if hz != 0 {
        TIMER_FREQ.store(hz, Ordering::Release);
    }
}

pub fn init_timer() {
    set_next_timer(10_000_000);
}

pub fn init_timer_hart() {
    set_next_timer(10_000_000);
}

fn read_frequency() -> u64 {
    10_000_000
}

pub fn read_time() -> u64 {
    let time: u64;
    unsafe {
        asm!("csrr {}, time", out(reg) time, options(nostack));
    }
    time
}

pub fn current_time_ns() -> u64 {
    let time = read_time();
    let freq = TIMER_FREQ.load(Ordering::Acquire);

    if freq == 0 {
        return 0;
    }

    (time * 1_000_000_000) / freq
}

pub fn current_time_us() -> u64 {
    let time = read_time();
    let freq = TIMER_FREQ.load(Ordering::Acquire);

    if freq == 0 {
        return 0;
    }

    (time * 1_000_000) / freq
}

pub fn set_next_timer(ticks: u64) {
    let current = read_time();
    let next = current + ticks;

    super::sbi::set_timer(next);
}

// SupervisorTimer ISR: arm the next deadline first (so the next tick
// can race the work below cleanly), clear sip.STIP, deliver the tick
// to the scheduler. Per-hart: SBI set_timer programs the calling
// hart's stimecmp, so each AP rearms its own deadline naturally.
pub fn handle_timer_interrupt() {
    set_next_timer(10_000_000);
    super::cpu::csr::clear_csr(super::cpu::csr::SIP, super::cpu::csr::SIP_STIP);
    crate::process::scheduler::preemption::tick::tick();
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

pub fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = TIMER_FREQ.load(Ordering::Acquire);
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000_000_000) / freq
}

pub fn ns_to_ticks(ns: u64) -> u64 {
    let freq = TIMER_FREQ.load(Ordering::Acquire);
    (ns * freq) / 1_000_000_000
}
