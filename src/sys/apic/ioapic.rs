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
use crate::sys::io::outb;

const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;

const IOAPIC_WIN: u32 = 0x10;

const IOAPIC_ID: u32 = 0x00;
const IOAPIC_VER: u32 = 0x01;
const IOAPIC_REDTBL: u32 = 0x10;

static IOAPIC_BASE: AtomicU64 = AtomicU64::new(IOAPIC_DEFAULT_BASE);
pub static IOAPIC_INIT: AtomicBool = AtomicBool::new(false);
static IOAPIC_MAX_REDIR: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(24);

unsafe fn ioapic_read(reg: u32) -> u32 {
    unsafe {
        let base = IOAPIC_BASE.load(Ordering::Relaxed);
        let regsel = base as *mut u32;
        let window = (base + IOAPIC_WIN as u64) as *mut u32;

        core::ptr::write_volatile(regsel, reg);
        core::ptr::read_volatile(window)
    }
}

unsafe fn ioapic_write(reg: u32, value: u32) {
    unsafe {
        let base = IOAPIC_BASE.load(Ordering::Relaxed);
        let regsel = base as *mut u32;
        let window = (base + IOAPIC_WIN as u64) as *mut u32;

        core::ptr::write_volatile(regsel, reg);
        core::ptr::write_volatile(window, value);
    }
}

pub fn init_ioapic() {
    if IOAPIC_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[APIC] Initializing I/O APIC...");

    disable_pic();

    unsafe {
        let ver = ioapic_read(IOAPIC_VER);
        let max_redir = ((ver >> 16) & 0xFF) as u8;
        IOAPIC_MAX_REDIR.store(max_redir + 1, Ordering::SeqCst);

        for i in 0..=max_redir {
            let reg_low = IOAPIC_REDTBL + (i as u32) * 2;
            ioapic_write(reg_low, 0x10000);
        }
    }

    IOAPIC_INIT.store(true, Ordering::SeqCst);

    let id = unsafe { (ioapic_read(IOAPIC_ID) >> 24) & 0x0F };
    let max_redir = IOAPIC_MAX_REDIR.load(Ordering::Relaxed);

    serial::print(b"[APIC] I/O APIC enabled, ID=");
    serial::print_dec(id as u64);
    serial::print(b" Max redirections=");
    serial::print_dec(max_redir as u64);
    serial::println(b"");
}

fn disable_pic() {
    serial::println(b"[APIC] Disabling legacy PIC (8259A)...");

    unsafe {
        outb(0x20, 0x11);
        outb(0xA0, 0x11);

        outb(0x21, 0x20);
        outb(0xA1, 0x28);

        outb(0x21, 0x04);
        outb(0xA1, 0x02);

        outb(0x21, 0x01);
        outb(0xA1, 0x01);

        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }

    serial::println(b"[APIC] Legacy PIC disabled");
}

pub fn ioapic_set_irq(irq: u8, vector: u8, dest: u8, flags: u32) {
    if !IOAPIC_INIT.load(Ordering::Relaxed) {
        init_ioapic();
    }

    let max_redir = IOAPIC_MAX_REDIR.load(Ordering::Relaxed);
    if irq >= max_redir {
        serial::println(b"[APIC] ERROR: IRQ out of range");
        return;
    }

    unsafe {
        let reg_low = IOAPIC_REDTBL + (irq as u32) * 2;
        let reg_high = reg_low + 1;

        let low = (vector as u32) | flags;
        let high = (dest as u32) << 24;

        ioapic_write(reg_high, high);
        ioapic_write(reg_low, low);
    }
}

pub fn enable_irq(irq: u8, vector: u8) {
    ioapic_set_irq(irq, vector, 0, 0);
}

pub fn disable_irq(irq: u8) {
    if !IOAPIC_INIT.load(Ordering::Relaxed) {
        return;
    }

    let max_redir = IOAPIC_MAX_REDIR.load(Ordering::Relaxed);
    if irq >= max_redir {
        return;
    }

    unsafe {
        let reg_low = IOAPIC_REDTBL + (irq as u32) * 2;
        let current = ioapic_read(reg_low);
        ioapic_write(reg_low, current | 0x10000);
    }
}
