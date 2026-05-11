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
//! The pool covers 64 vectors at `BROKER_VEC_MIN..=BROKER_VEC_MAX`
//! (`0x81..=0xC0`). Both legacy INTx grants and MSI/MSI-X grants
//! terminate here — the LAPIC vectors them to one of these stubs
//! whether the IO-APIC or an MSI-X table did the original routing.
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

broker_irq_stub!(irq_broker_81, 0x81);
broker_irq_stub!(irq_broker_82, 0x82);
broker_irq_stub!(irq_broker_83, 0x83);
broker_irq_stub!(irq_broker_84, 0x84);
broker_irq_stub!(irq_broker_85, 0x85);
broker_irq_stub!(irq_broker_86, 0x86);
broker_irq_stub!(irq_broker_87, 0x87);
broker_irq_stub!(irq_broker_88, 0x88);
broker_irq_stub!(irq_broker_89, 0x89);
broker_irq_stub!(irq_broker_8a, 0x8A);
broker_irq_stub!(irq_broker_8b, 0x8B);
broker_irq_stub!(irq_broker_8c, 0x8C);
broker_irq_stub!(irq_broker_8d, 0x8D);
broker_irq_stub!(irq_broker_8e, 0x8E);
broker_irq_stub!(irq_broker_8f, 0x8F);
broker_irq_stub!(irq_broker_90, 0x90);
broker_irq_stub!(irq_broker_91, 0x91);
broker_irq_stub!(irq_broker_92, 0x92);
broker_irq_stub!(irq_broker_93, 0x93);
broker_irq_stub!(irq_broker_94, 0x94);
broker_irq_stub!(irq_broker_95, 0x95);
broker_irq_stub!(irq_broker_96, 0x96);
broker_irq_stub!(irq_broker_97, 0x97);
broker_irq_stub!(irq_broker_98, 0x98);
broker_irq_stub!(irq_broker_99, 0x99);
broker_irq_stub!(irq_broker_9a, 0x9A);
broker_irq_stub!(irq_broker_9b, 0x9B);
broker_irq_stub!(irq_broker_9c, 0x9C);
broker_irq_stub!(irq_broker_9d, 0x9D);
broker_irq_stub!(irq_broker_9e, 0x9E);
broker_irq_stub!(irq_broker_9f, 0x9F);
broker_irq_stub!(irq_broker_a0, 0xA0);
broker_irq_stub!(irq_broker_a1, 0xA1);
broker_irq_stub!(irq_broker_a2, 0xA2);
broker_irq_stub!(irq_broker_a3, 0xA3);
broker_irq_stub!(irq_broker_a4, 0xA4);
broker_irq_stub!(irq_broker_a5, 0xA5);
broker_irq_stub!(irq_broker_a6, 0xA6);
broker_irq_stub!(irq_broker_a7, 0xA7);
broker_irq_stub!(irq_broker_a8, 0xA8);
broker_irq_stub!(irq_broker_a9, 0xA9);
broker_irq_stub!(irq_broker_aa, 0xAA);
broker_irq_stub!(irq_broker_ab, 0xAB);
broker_irq_stub!(irq_broker_ac, 0xAC);
broker_irq_stub!(irq_broker_ad, 0xAD);
broker_irq_stub!(irq_broker_ae, 0xAE);
broker_irq_stub!(irq_broker_af, 0xAF);
broker_irq_stub!(irq_broker_b0, 0xB0);
broker_irq_stub!(irq_broker_b1, 0xB1);
broker_irq_stub!(irq_broker_b2, 0xB2);
broker_irq_stub!(irq_broker_b3, 0xB3);
broker_irq_stub!(irq_broker_b4, 0xB4);
broker_irq_stub!(irq_broker_b5, 0xB5);
broker_irq_stub!(irq_broker_b6, 0xB6);
broker_irq_stub!(irq_broker_b7, 0xB7);
broker_irq_stub!(irq_broker_b8, 0xB8);
broker_irq_stub!(irq_broker_b9, 0xB9);
broker_irq_stub!(irq_broker_ba, 0xBA);
broker_irq_stub!(irq_broker_bb, 0xBB);
broker_irq_stub!(irq_broker_bc, 0xBC);
broker_irq_stub!(irq_broker_bd, 0xBD);
broker_irq_stub!(irq_broker_be, 0xBE);
broker_irq_stub!(irq_broker_bf, 0xBF);
broker_irq_stub!(irq_broker_c0, 0xC0);

pub type IrqHandler = extern "x86-interrupt" fn(InterruptStackFrame);

pub const STUBS: [IrqHandler; super::vectors::BROKER_VEC_COUNT] = [
    irq_broker_81,
    irq_broker_82,
    irq_broker_83,
    irq_broker_84,
    irq_broker_85,
    irq_broker_86,
    irq_broker_87,
    irq_broker_88,
    irq_broker_89,
    irq_broker_8a,
    irq_broker_8b,
    irq_broker_8c,
    irq_broker_8d,
    irq_broker_8e,
    irq_broker_8f,
    irq_broker_90,
    irq_broker_91,
    irq_broker_92,
    irq_broker_93,
    irq_broker_94,
    irq_broker_95,
    irq_broker_96,
    irq_broker_97,
    irq_broker_98,
    irq_broker_99,
    irq_broker_9a,
    irq_broker_9b,
    irq_broker_9c,
    irq_broker_9d,
    irq_broker_9e,
    irq_broker_9f,
    irq_broker_a0,
    irq_broker_a1,
    irq_broker_a2,
    irq_broker_a3,
    irq_broker_a4,
    irq_broker_a5,
    irq_broker_a6,
    irq_broker_a7,
    irq_broker_a8,
    irq_broker_a9,
    irq_broker_aa,
    irq_broker_ab,
    irq_broker_ac,
    irq_broker_ad,
    irq_broker_ae,
    irq_broker_af,
    irq_broker_b0,
    irq_broker_b1,
    irq_broker_b2,
    irq_broker_b3,
    irq_broker_b4,
    irq_broker_b5,
    irq_broker_b6,
    irq_broker_b7,
    irq_broker_b8,
    irq_broker_b9,
    irq_broker_ba,
    irq_broker_bb,
    irq_broker_bc,
    irq_broker_bd,
    irq_broker_be,
    irq_broker_bf,
    irq_broker_c0,
];
