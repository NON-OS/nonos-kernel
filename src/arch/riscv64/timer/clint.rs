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

const CLINT_MSIP_BASE: u64 = 0x0000;
const CLINT_MTIMECMP_BASE: u64 = 0x4000;
const CLINT_MTIME: u64 = 0xBFF8;

static CLINT_BASE: AtomicU64 = AtomicU64::new(0x0200_0000);

pub struct Clint {
    base: u64,
}

impl Clint {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn mtime(&self) -> u64 {
        let addr = self.base + CLINT_MTIME;
        unsafe { read_volatile(addr as *const u64) }
    }

    pub fn set_mtimecmp(&self, hart: usize, value: u64) {
        let addr = self.base + CLINT_MTIMECMP_BASE + (hart as u64 * 8);
        unsafe {
            write_volatile(addr as *mut u64, value);
        }
    }

    pub fn get_mtimecmp(&self, hart: usize) -> u64 {
        let addr = self.base + CLINT_MTIMECMP_BASE + (hart as u64 * 8);
        unsafe { read_volatile(addr as *const u64) }
    }

    pub fn send_ipi(&self, hart: usize) {
        let addr = self.base + CLINT_MSIP_BASE + (hart as u64 * 4);
        unsafe {
            write_volatile(addr as *mut u32, 1);
        }
    }

    pub fn clear_ipi(&self, hart: usize) {
        let addr = self.base + CLINT_MSIP_BASE + (hart as u64 * 4);
        unsafe {
            write_volatile(addr as *mut u32, 0);
        }
    }

    pub fn is_ipi_pending(&self, hart: usize) -> bool {
        let addr = self.base + CLINT_MSIP_BASE + (hart as u64 * 4);
        unsafe { read_volatile(addr as *const u32) != 0 }
    }
}

pub fn set_clint_base(base: u64) {
    CLINT_BASE.store(base, Ordering::Release);
}

pub fn clint_base() -> u64 {
    CLINT_BASE.load(Ordering::Acquire)
}

pub fn set_timer_interrupt(ticks: u64) {
    let base = clint_base();
    let clint = Clint::new(base);
    let hart = super::super::cpu::hart_id();
    let current = clint.mtime();
    clint.set_mtimecmp(hart, current + ticks);
}

pub fn clear_timer_interrupt() {
    let base = clint_base();
    let clint = Clint::new(base);
    let hart = super::super::cpu::hart_id();
    clint.set_mtimecmp(hart, u64::MAX);
}

pub fn read_mtime() -> u64 {
    let base = clint_base();
    let clint = Clint::new(base);
    clint.mtime()
}

pub fn send_ipi(hart: usize) {
    let base = clint_base();
    let clint = Clint::new(base);
    clint.send_ipi(hart);
}

pub fn clear_ipi(hart: usize) {
    let base = clint_base();
    let clint = Clint::new(base);
    clint.clear_ipi(hart);
}
