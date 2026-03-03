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
use x86_64::{PhysAddr, VirtAddr};

use super::super::types::I2cSpeed;
use super::registers::I2C_MMIO_SIZE;
use crate::memory::nonos_paging::{map_page, PagePermissions};

static NEXT_I2C_MMIO: AtomicU64 = AtomicU64::new(0xFFFF_8900_0000_0000);

fn map_i2c_mmio(phys_addr: u64) -> Option<u64> {
    let phys = PhysAddr::new(phys_addr);
    let virt_base = NEXT_I2C_MMIO.fetch_add(I2C_MMIO_SIZE as u64, Ordering::SeqCst);
    let virt = VirtAddr::new(virt_base);

    let permissions = PagePermissions::READ
        | PagePermissions::WRITE
        | PagePermissions::NO_CACHE
        | PagePermissions::DEVICE;

    if let Err(_) = map_page(virt, phys, permissions) {
        return None;
    }

    Some(virt_base)
}

pub struct DesignWareI2c {
    pub(super) base: u64,
    pub(super) speed: I2cSpeed,
    pub(super) input_clock_hz: u32,
    pub(super) tx_fifo_depth: u32,
    pub(super) rx_fifo_depth: u32,
    pub(super) initialized: AtomicBool,
}

impl DesignWareI2c {
    pub fn new(phys_base: u64, input_clock_hz: u32) -> Option<Self> {
        let virt_base = map_i2c_mmio(phys_base)?;

        Some(Self {
            base: virt_base,
            speed: I2cSpeed::Fast,
            input_clock_hz,
            tx_fifo_depth: 64,
            rx_fifo_depth: 64,
            initialized: AtomicBool::new(false),
        })
    }

    pub fn base_address(&self) -> u64 {
        self.base
    }

    pub(super) fn read_reg(&self, offset: u64) -> u32 {
        // SAFETY: MMIO register access to valid controller address
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    pub(super) fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: MMIO register access to valid controller address
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}

impl Clone for DesignWareI2c {
    fn clone(&self) -> Self {
        Self {
            base: self.base,
            speed: self.speed,
            input_clock_hz: self.input_clock_hz,
            tx_fifo_depth: self.tx_fifo_depth,
            rx_fifo_depth: self.rx_fifo_depth,
            initialized: AtomicBool::new(self.initialized.load(Ordering::Relaxed)),
        }
    }
}

pub(super) fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}
