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

const GICR_CTLR: u64 = 0x0000;
const GICR_IIDR: u64 = 0x0004;
const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;

const GICR_SGI_BASE: u64 = 0x10000;
const GICR_IGROUPR0: u64 = GICR_SGI_BASE + 0x0080;
const GICR_ISENABLER0: u64 = GICR_SGI_BASE + 0x0100;
const GICR_ICENABLER0: u64 = GICR_SGI_BASE + 0x0180;
const GICR_ISPENDR0: u64 = GICR_SGI_BASE + 0x0200;
const GICR_ICPENDR0: u64 = GICR_SGI_BASE + 0x0280;
const GICR_ISACTIVER0: u64 = GICR_SGI_BASE + 0x0300;
const GICR_ICACTIVER0: u64 = GICR_SGI_BASE + 0x0380;
const GICR_IPRIORITYR: u64 = GICR_SGI_BASE + 0x0400;
const GICR_ICFGR0: u64 = GICR_SGI_BASE + 0x0C00;
const GICR_ICFGR1: u64 = GICR_SGI_BASE + 0x0C04;
const GICR_IGRPMODR0: u64 = GICR_SGI_BASE + 0x0D00;

const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

pub struct GicRedistributor {
    base: u64,
}

impl GicRedistributor {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn init(&self) {
        self.wake();

        self.write_reg(GICR_IGROUPR0, 0xFFFF_FFFF);
        self.write_reg(GICR_IGRPMODR0, 0);

        for i in (0..32u32).step_by(4) {
            self.write_reg(GICR_IPRIORITYR + i as u64, 0xA0A0_A0A0);
        }

        self.write_reg(GICR_ICENABLER0, 0xFFFF_0000);
        self.write_reg(GICR_ISENABLER0, 0x0000_FFFF);
    }

    fn wake(&self) {
        let mut waker = self.read_reg(GICR_WAKER);

        if waker & WAKER_PROCESSOR_SLEEP != 0 {
            waker &= !WAKER_PROCESSOR_SLEEP;
            self.write_reg(GICR_WAKER, waker);

            while self.read_reg(GICR_WAKER) & WAKER_CHILDREN_ASLEEP != 0 {
                core::hint::spin_loop();
            }
        }
    }

    pub fn enable_irq(&self, irq: u32) {
        if irq >= 32 {
            return;
        }
        let bit = 1u32 << irq;
        self.write_reg(GICR_ISENABLER0, bit);
    }

    pub fn disable_irq(&self, irq: u32) {
        if irq >= 32 {
            return;
        }
        let bit = 1u32 << irq;
        self.write_reg(GICR_ICENABLER0, bit);
    }

    pub fn set_pending(&self, irq: u32) {
        if irq >= 32 {
            return;
        }
        let bit = 1u32 << irq;
        self.write_reg(GICR_ISPENDR0, bit);
    }

    pub fn clear_pending(&self, irq: u32) {
        if irq >= 32 {
            return;
        }
        let bit = 1u32 << irq;
        self.write_reg(GICR_ICPENDR0, bit);
    }

    pub fn set_priority(&self, irq: u32, priority: u8) {
        if irq >= 32 {
            return;
        }
        let reg = GICR_IPRIORITYR + irq as u64;
        let addr = (self.base + reg) as *mut u8;
        unsafe {
            write_volatile(addr, priority);
        }
    }

    pub fn set_config(&self, irq: u32, edge: bool) {
        if irq >= 32 {
            return;
        }

        let reg = if irq < 16 { GICR_ICFGR0 } else { GICR_ICFGR1 };
        let shift = (irq % 16) * 2;
        let mut val = self.read_reg(reg);

        if edge {
            val |= 2 << shift;
        } else {
            val &= !(2 << shift);
        }

        self.write_reg(reg, val);
    }

    pub fn affinity(&self) -> u64 {
        self.read_reg64(GICR_TYPER) >> 32
    }

    fn read_reg(&self, offset: u64) -> u32 {
        let addr = (self.base + offset) as *const u32;
        unsafe { read_volatile(addr) }
    }

    fn write_reg(&self, offset: u64, value: u32) {
        let addr = (self.base + offset) as *mut u32;
        unsafe { write_volatile(addr, value) }
    }

    fn read_reg64(&self, offset: u64) -> u64 {
        let addr = (self.base + offset) as *const u64;
        unsafe { read_volatile(addr) }
    }
}
