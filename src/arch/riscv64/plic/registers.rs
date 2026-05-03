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

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

const PLIC_PRIORITY_BASE: u64 = 0x0000;
const PLIC_PENDING_BASE: u64 = 0x1000;
const PLIC_ENABLE_BASE: u64 = 0x2000;
const PLIC_THRESHOLD_BASE: u64 = 0x20_0000;
const PLIC_CLAIM_BASE: u64 = 0x20_0004;

const PLIC_ENABLE_STRIDE: u64 = 0x80;
const PLIC_CONTEXT_STRIDE: u64 = 0x1000;

const MAX_INTERRUPTS: u32 = 1024;

static PLIC_BASE: AtomicU64 = AtomicU64::new(0x0C00_0000);

pub struct Plic {
    base: u64,
}

impl Plic {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn init(&self) {
        for irq in 1..MAX_INTERRUPTS {
            self.set_priority(irq, 0);
        }

        let hart = super::super::cpu::hart_id();
        self.set_threshold(hart, 0);
    }

    pub fn set_priority(&self, irq: u32, priority: u8) {
        if irq == 0 || irq >= MAX_INTERRUPTS {
            return;
        }

        let addr = self.base + PLIC_PRIORITY_BASE + (irq as u64 * 4);
        unsafe {
            write_volatile(addr as *mut u32, priority as u32);
        }
    }

    pub fn get_priority(&self, irq: u32) -> u8 {
        if irq == 0 || irq >= MAX_INTERRUPTS {
            return 0;
        }

        let addr = self.base + PLIC_PRIORITY_BASE + (irq as u64 * 4);
        unsafe { read_volatile(addr as *const u32) as u8 }
    }

    pub fn enable(&self, hart: usize, irq: u32) {
        if irq == 0 || irq >= MAX_INTERRUPTS {
            return;
        }

        let context = hart * 2 + 1;
        let reg = irq / 32;
        let bit = irq % 32;

        let addr =
            self.base + PLIC_ENABLE_BASE + (context as u64 * PLIC_ENABLE_STRIDE) + (reg as u64 * 4);

        unsafe {
            let val = read_volatile(addr as *const u32);
            write_volatile(addr as *mut u32, val | (1 << bit));
        }
    }

    pub fn disable(&self, hart: usize, irq: u32) {
        if irq == 0 || irq >= MAX_INTERRUPTS {
            return;
        }

        let context = hart * 2 + 1;
        let reg = irq / 32;
        let bit = irq % 32;

        let addr =
            self.base + PLIC_ENABLE_BASE + (context as u64 * PLIC_ENABLE_STRIDE) + (reg as u64 * 4);

        unsafe {
            let val = read_volatile(addr as *const u32);
            write_volatile(addr as *mut u32, val & !(1 << bit));
        }
    }

    pub fn set_threshold(&self, hart: usize, threshold: u8) {
        let context = hart * 2 + 1;
        let addr = self.base + PLIC_THRESHOLD_BASE + (context as u64 * PLIC_CONTEXT_STRIDE);

        unsafe {
            write_volatile(addr as *mut u32, threshold as u32);
        }
    }

    pub fn claim(&self, hart: usize) -> Option<u32> {
        let context = hart * 2 + 1;
        let addr = self.base + PLIC_CLAIM_BASE + (context as u64 * PLIC_CONTEXT_STRIDE);

        let irq = unsafe { read_volatile(addr as *const u32) };

        if irq == 0 {
            None
        } else {
            Some(irq)
        }
    }

    pub fn complete(&self, hart: usize, irq: u32) {
        let context = hart * 2 + 1;
        let addr = self.base + PLIC_CLAIM_BASE + (context as u64 * PLIC_CONTEXT_STRIDE);

        unsafe {
            write_volatile(addr as *mut u32, irq);
        }
    }

    pub fn is_pending(&self, irq: u32) -> bool {
        if irq == 0 || irq >= MAX_INTERRUPTS {
            return false;
        }

        let reg = irq / 32;
        let bit = irq % 32;

        let addr = self.base + PLIC_PENDING_BASE + (reg as u64 * 4);
        let val = unsafe { read_volatile(addr as *const u32) };

        (val & (1 << bit)) != 0
    }
}

pub fn init_plic(base: u64) {
    PLIC_BASE.store(base, Ordering::Release);

    let plic = Plic::new(base);
    plic.init();
}

pub fn enable_irq(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    let hart = super::super::cpu::hart_id();
    plic.set_priority(irq, 1);
    plic.enable(hart, irq);
}

pub fn disable_irq(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    let hart = super::super::cpu::hart_id();
    plic.disable(hart, irq);
}

pub fn set_priority(irq: u32, priority: u8) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    plic.set_priority(irq, priority);
}

pub fn set_threshold(hart: usize, threshold: u8) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    plic.set_threshold(hart, threshold);
}

pub fn claim_interrupt() -> Option<u32> {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    let hart = super::super::cpu::hart_id();
    plic.claim(hart)
}

pub fn complete_interrupt(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    let plic = Plic::new(base);
    let hart = super::super::cpu::hart_id();
    plic.complete(hart, irq);
}
