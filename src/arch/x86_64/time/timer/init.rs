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

use super::state::{ACTIVE_TIMERS, BOOT_TIME, HPET_BASE, TIMER_INITIALIZED, TSC_FREQUENCY};
use super::tsc::rdtsc;
use super::hpet::{configure_hpet, configure_hpet_for_timing, detect_hpet};

pub fn init() {
    let boot_tsc = rdtsc();
    BOOT_TIME.store(boot_tsc, Ordering::SeqCst);
    let tsc_freq = calibrate_tsc_frequency();
    TSC_FREQUENCY.store(tsc_freq, Ordering::SeqCst);
    if let Some(hpet_base) = detect_hpet() {
        HPET_BASE.store(hpet_base, Ordering::SeqCst);
        configure_hpet_for_timing(hpet_base);
    }
    ACTIVE_TIMERS.lock().clear();
    TIMER_INITIALIZED.store(true, Ordering::SeqCst);
    if let Some(logger) = crate::log::logger::try_get_logger() {
        if let Some(log_mgr) = logger.lock().as_mut() {
            log_mgr.log(crate::log::nonos_logger::Severity::Info, &alloc::format!("[TIMER] Initialized with TSC frequency: {} Hz", tsc_freq));
        }
    }
}

fn calibrate_tsc_frequency() -> u64 {
    unsafe {
        crate::arch::x86_64::port::outb(0x43, 0xB0);
        crate::arch::x86_64::port::outb(0x42, 0xFF);
        crate::arch::x86_64::port::outb(0x42, 0xFF);
        let speaker_port = crate::arch::x86_64::port::inb(0x61);
        crate::arch::x86_64::port::outb(0x61, speaker_port | 0x03);
        while (crate::arch::x86_64::port::inb(0x61) & 0x20) == 0 {}
        let start_tsc = rdtsc();
        while (crate::arch::x86_64::port::inb(0x61) & 0x20) != 0 {}
        let end_tsc = rdtsc();
        crate::arch::x86_64::port::outb(0x61, speaker_port);
        let tsc_ticks = end_tsc - start_tsc;
        let time_ns = 54925484;
        (tsc_ticks * 1_000_000_000) / time_ns
    }
}

pub fn init_with_freq(freq_hz: u32) {
    BOOT_TIME.store(rdtsc(), Ordering::SeqCst);
    unsafe {
        let divisor = 1193182 / freq_hz;
        crate::arch::x86_64::port::outb(0x43, 0x36);
        crate::arch::x86_64::port::outb(0x40, (divisor & 0xFF) as u8);
        crate::arch::x86_64::port::outb(0x40, ((divisor >> 8) & 0xFF) as u8);
    }
    if let Some(hpet_base) = detect_hpet() {
        configure_hpet(hpet_base, freq_hz);
        crate::log_info!("HPET configured at frequency {} Hz", freq_hz);
    } else {
        crate::log_info!("PIT configured at frequency {} Hz", freq_hz);
    }
}
