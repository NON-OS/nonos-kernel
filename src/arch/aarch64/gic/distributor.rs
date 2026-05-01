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

const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IIDR: u64 = 0x0008;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ICENABLER: u64 = 0x0180;
const GICD_ISPENDR: u64 = 0x0200;
const GICD_ICPENDR: u64 = 0x0280;
const GICD_ISACTIVER: u64 = 0x0300;
const GICD_ICACTIVER: u64 = 0x0380;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_ITARGETSR: u64 = 0x0800;
const GICD_ICFGR: u64 = 0x0C00;
const GICD_IGRPMODR: u64 = 0x0D00;
const GICD_IROUTER: u64 = 0x6000;

const CTLR_ENABLE_G0: u32 = 1 << 0;
const CTLR_ENABLE_G1NS: u32 = 1 << 1;
const CTLR_ENABLE_G1S: u32 = 1 << 2;
const CTLR_ARE_S: u32 = 1 << 4;
const CTLR_ARE_NS: u32 = 1 << 5;
const CTLR_DS: u32 = 1 << 6;

pub struct GicDistributor {
    base: u64,
}

impl GicDistributor {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn init(&self) {
        self.write_reg(GICD_CTLR, 0);

        let typer = self.read_reg(GICD_TYPER);
        let num_irqs = ((typer & 0x1F) + 1) * 32;

        for i in (32..num_irqs).step_by(32) {
            self.write_reg(GICD_ICENABLER + (i / 32) * 4, 0xFFFF_FFFF);
        }

        for i in (32..num_irqs).step_by(32) {
            self.write_reg(GICD_ICPENDR + (i / 32) * 4, 0xFFFF_FFFF);
        }

        for i in (32..num_irqs).step_by(32) {
            self.write_reg(GICD_IGROUPR + (i / 32) * 4, 0xFFFF_FFFF);
        }

        for i in (32..num_irqs).step_by(4) {
            self.write_reg(GICD_IPRIORITYR + i, 0xA0A0_A0A0);
        }

        let ctlr = CTLR_ENABLE_G0 | CTLR_ENABLE_G1NS | CTLR_ARE_S | CTLR_ARE_NS;
        self.write_reg(GICD_CTLR, ctlr);
    }

    pub fn enable_irq(&self, irq: u32) {
        let reg = GICD_ISENABLER + ((irq / 32) * 4) as u64;
        let bit = 1u32 << (irq % 32);
        self.write_reg(reg, bit);
    }

    pub fn disable_irq(&self, irq: u32) {
        let reg = GICD_ICENABLER + ((irq / 32) * 4) as u64;
        let bit = 1u32 << (irq % 32);
        self.write_reg(reg, bit);
    }

    pub fn set_pending(&self, irq: u32) {
        let reg = GICD_ISPENDR + ((irq / 32) * 4) as u64;
        let bit = 1u32 << (irq % 32);
        self.write_reg(reg, bit);
    }

    pub fn clear_pending(&self, irq: u32) {
        let reg = GICD_ICPENDR + ((irq / 32) * 4) as u64;
        let bit = 1u32 << (irq % 32);
        self.write_reg(reg, bit);
    }

    pub fn set_priority(&self, irq: u32, priority: u8) {
        let reg = GICD_IPRIORITYR + irq as u64;
        let addr = (self.base + reg) as *mut u8;
        unsafe {
            write_volatile(addr, priority);
        }
    }

    pub fn set_target(&self, irq: u32, target: u8) {
        let reg = GICD_ITARGETSR + irq as u64;
        let addr = (self.base + reg) as *mut u8;
        unsafe {
            write_volatile(addr, target);
        }
    }

    pub fn set_config(&self, irq: u32, edge: bool) {
        let reg = GICD_ICFGR + ((irq / 16) * 4) as u64;
        let shift = (irq % 16) * 2;
        let mut val = self.read_reg(reg);

        if edge {
            val |= 2 << shift;
        } else {
            val &= !(2 << shift);
        }

        self.write_reg(reg, val);
    }

    pub fn set_route(&self, irq: u32, affinity: u64) {
        let reg = GICD_IROUTER + (irq as u64) * 8;
        self.write_reg64(reg, affinity);
    }

    pub fn num_irqs(&self) -> u32 {
        let typer = self.read_reg(GICD_TYPER);
        ((typer & 0x1F) + 1) * 32
    }

    fn read_reg(&self, offset: u64) -> u32 {
        let addr = (self.base + offset) as *const u32;
        unsafe { read_volatile(addr) }
    }

    fn write_reg(&self, offset: u64, value: u32) {
        let addr = (self.base + offset) as *mut u32;
        unsafe { write_volatile(addr, value) }
    }

    fn write_reg64(&self, offset: u64, value: u64) {
        let addr = (self.base + offset) as *mut u64;
        unsafe { write_volatile(addr, value) }
    }
}
