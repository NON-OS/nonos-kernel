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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sys::serial;

const LOCAL_APIC_DEFAULT_BASE: u64 = 0xFEE0_0000;

const LAPIC_ID: u32 = 0x020;
const LAPIC_VERSION: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080;
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_ESR: u32 = 0x280;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_LVT_ERROR: u32 = 0x370;
const LAPIC_TIMER_INIT: u32 = 0x380;
const LAPIC_TIMER_DIV: u32 = 0x3E0;

const SPURIOUS_VECTOR: u32 = 0xFF;

pub const TIMER_VECTOR: u8 = 0x20;

static LAPIC_BASE: AtomicU64 = AtomicU64::new(LOCAL_APIC_DEFAULT_BASE);
pub static LAPIC_INIT: AtomicBool = AtomicBool::new(false);

unsafe fn lapic_read(reg: u32) -> u32 {
    unsafe {
        let base = LAPIC_BASE.load(Ordering::Relaxed);
        let ptr = (base + reg as u64) as *const u32;
        core::ptr::read_volatile(ptr)
    }
}

unsafe fn lapic_write(reg: u32, value: u32) {
    unsafe {
        let base = LAPIC_BASE.load(Ordering::Relaxed);
        let ptr = (base + reg as u64) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }
}

pub fn init_local_apic() {
    if LAPIC_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[APIC] Initializing Local APIC...");

    unsafe {
        let base = LOCAL_APIC_DEFAULT_BASE;
        LAPIC_BASE.store(base, Ordering::SeqCst);

        let svr = (1 << 8) | SPURIOUS_VECTOR;
        lapic_write(LAPIC_SVR, svr);

        lapic_write(LAPIC_TPR, 0);

        lapic_write(LAPIC_ESR, 0);
        let _ = lapic_read(LAPIC_ESR);

        lapic_write(LAPIC_LVT_TIMER, 0x10000);
        lapic_write(LAPIC_LVT_LINT0, 0x10000);
        lapic_write(LAPIC_LVT_LINT1, 0x10000);
        lapic_write(LAPIC_LVT_ERROR, 0x10000);
    }

    LAPIC_INIT.store(true, Ordering::SeqCst);

    let version = unsafe { lapic_read(LAPIC_VERSION) };
    let id = unsafe { lapic_read(LAPIC_ID) >> 24 };

    serial::print(b"[APIC] Local APIC enabled, ID=");
    serial::print_dec(id as u64);
    serial::print(b" Version=0x");
    serial::print_hex((version & 0xFF) as u64);
    serial::println(b"");
}

#[inline]
pub fn eoi() {
    unsafe {
        lapic_write(LAPIC_EOI, 0);
    }
}

pub fn setup_timer(frequency_hz: u32) {
    if !LAPIC_INIT.load(Ordering::Relaxed) {
        init_local_apic();
    }

    serial::print(b"[APIC] Setting up timer at ");
    serial::print_dec(frequency_hz as u64);
    serial::println(b" Hz");

    unsafe {
        lapic_write(LAPIC_TIMER_DIV, 0x03);

        let timer_config = (TIMER_VECTOR as u32) | (1 << 17);
        lapic_write(LAPIC_LVT_TIMER, timer_config);

        let initial_count = 10_000_000 / frequency_hz;
        lapic_write(LAPIC_TIMER_INIT, initial_count);
    }
}

pub fn stop_timer() {
    unsafe {
        lapic_write(LAPIC_LVT_TIMER, 0x10000);
        lapic_write(LAPIC_TIMER_INIT, 0);
    }
}
