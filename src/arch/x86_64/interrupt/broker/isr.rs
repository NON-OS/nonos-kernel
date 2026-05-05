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

//! Per-vector ISR stubs for the broker IRQ pool. Each stub is an
//! `extern "x86-interrupt"` function the IDT can install directly.
//! All stubs tail-call the broker dispatcher with their own vector
//! number; the dispatcher does the bookkeeping and acks the LAPIC.
//!
//! Hard-IRQ rules in this path:
//!   * never take a sleeping or contended lock
//!   * never call into IPC, paging, or the scheduler
//!   * never allocate
//!   * the only writes are the per-grant atomic counters and the
//!     IO-APIC mask register (a pair of MMIO writes serialised by
//!     a short spin-lock per chip)

use x86_64::structures::idt::InterruptStackFrame;

use crate::hardware::broker::irq::dispatch;

macro_rules! broker_irq_stub {
    ($name:ident, $vector:expr) => {
        pub extern "x86-interrupt" fn $name(_frame: InterruptStackFrame) {
            dispatch::on_vector($vector);
        }
    };
}

broker_irq_stub!(irq_broker_60, 0x60);
broker_irq_stub!(irq_broker_61, 0x61);
broker_irq_stub!(irq_broker_62, 0x62);
broker_irq_stub!(irq_broker_63, 0x63);
broker_irq_stub!(irq_broker_64, 0x64);
broker_irq_stub!(irq_broker_65, 0x65);
broker_irq_stub!(irq_broker_66, 0x66);
broker_irq_stub!(irq_broker_67, 0x67);
broker_irq_stub!(irq_broker_68, 0x68);
broker_irq_stub!(irq_broker_69, 0x69);
broker_irq_stub!(irq_broker_6a, 0x6A);
broker_irq_stub!(irq_broker_6b, 0x6B);
broker_irq_stub!(irq_broker_6c, 0x6C);
broker_irq_stub!(irq_broker_6d, 0x6D);
broker_irq_stub!(irq_broker_6e, 0x6E);
broker_irq_stub!(irq_broker_6f, 0x6F);

pub type IrqHandler = extern "x86-interrupt" fn(InterruptStackFrame);

pub const STUBS: [IrqHandler; super::vectors::BROKER_VEC_COUNT] = [
    irq_broker_60,
    irq_broker_61,
    irq_broker_62,
    irq_broker_63,
    irq_broker_64,
    irq_broker_65,
    irq_broker_66,
    irq_broker_67,
    irq_broker_68,
    irq_broker_69,
    irq_broker_6a,
    irq_broker_6b,
    irq_broker_6c,
    irq_broker_6d,
    irq_broker_6e,
    irq_broker_6f,
];
