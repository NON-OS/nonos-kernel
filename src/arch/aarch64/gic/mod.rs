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

pub mod cpu;
pub mod distributor;
pub mod icc;
pub mod redistributor;

pub use cpu::init_gic_cpu;
pub use distributor::GicDistributor;
pub use icc::{acknowledge_interrupt, end_interrupt, set_priority_mask};
pub use redistributor::GicRedistributor;

use core::sync::atomic::{AtomicU64, Ordering};

static DIST_BASE: AtomicU64 = AtomicU64::new(0);
static REDIST_BASE: AtomicU64 = AtomicU64::new(0);

pub struct Gic {
    distributor: GicDistributor,
    redistributor: GicRedistributor,
}

impl Gic {
    pub fn new(dist_base: u64, redist_base: u64) -> Self {
        Self {
            distributor: GicDistributor::new(dist_base),
            redistributor: GicRedistributor::new(redist_base),
        }
    }

    pub fn init(&mut self) {
        self.distributor.init();
        self.redistributor.init();
        icc::init();
    }

    pub fn enable_irq(&self, irq: u32) {
        if irq < 32 {
            self.redistributor.enable_irq(irq);
        } else {
            self.distributor.enable_irq(irq);
        }
    }

    pub fn disable_irq(&self, irq: u32) {
        if irq < 32 {
            self.redistributor.disable_irq(irq);
        } else {
            self.distributor.disable_irq(irq);
        }
    }

    pub fn set_priority(&self, irq: u32, priority: u8) {
        if irq < 32 {
            self.redistributor.set_priority(irq, priority);
        } else {
            self.distributor.set_priority(irq, priority);
        }
    }

    pub fn set_target(&self, irq: u32, target: u8) {
        self.distributor.set_target(irq, target);
    }

    pub fn set_config(&self, irq: u32, edge: bool) {
        if irq < 32 {
            self.redistributor.set_config(irq, edge);
        } else {
            self.distributor.set_config(irq, edge);
        }
    }
}

pub fn init_gic(dist_base: u64, redist_base: u64) {
    DIST_BASE.store(dist_base, Ordering::Release);
    REDIST_BASE.store(redist_base, Ordering::Release);

    let mut gic = Gic::new(dist_base, redist_base);
    gic.init();
}

pub fn enable_irq(irq: u32) {
    let dist = DIST_BASE.load(Ordering::Acquire);
    let redist = REDIST_BASE.load(Ordering::Acquire);
    let gic = Gic::new(dist, redist);
    gic.enable_irq(irq);
}

pub fn disable_irq(irq: u32) {
    let dist = DIST_BASE.load(Ordering::Acquire);
    let redist = REDIST_BASE.load(Ordering::Acquire);
    let gic = Gic::new(dist, redist);
    gic.disable_irq(irq);
}

pub fn send_sgi(target: u32, intid: u32) -> Result<(), ()> {
    icc::send_sgi(target, intid)
}
