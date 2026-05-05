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

//! Hard-IRQ dispatcher. Each broker vector ISR tail-calls
//! `on_vector`. The dispatcher must not allocate, must not take
//! contended locks, must not touch IPC, paging, or the scheduler.
//! It bumps the per-grant counter, masks the GSI at the IO-APIC,
//! and EOIs the LAPIC. The capsule sees the increment via
//! `MkIrqPoll` from normal syscall context.

use core::sync::atomic::Ordering;

use super::slots::SLOTS;
use crate::arch::interrupt::broker::slot_of;

const SEQ_SATURATION: u64 = u64::MAX - 1;

#[inline]
pub fn on_vector(vector: u8) {
    let slot_idx = match slot_of(vector) {
        Some(i) => i,
        None => {
            crate::interrupts::apic::send_eoi();
            return;
        }
    };
    let slot = &SLOTS[slot_idx];
    if !slot.active.load(Ordering::Acquire) {
        crate::interrupts::apic::send_eoi();
        return;
    }

    let gsi = slot.gsi.load(Ordering::Relaxed);
    if crate::arch::interrupt::ioapic::mask(gsi, true).is_err() {
        slot.overflow.fetch_add(1, Ordering::AcqRel);
        crate::interrupts::apic::send_eoi();
        return;
    }

    let prev = slot.seq.fetch_add(1, Ordering::AcqRel);
    if prev >= SEQ_SATURATION {
        slot.overflow.fetch_add(1, Ordering::AcqRel);
    }

    crate::interrupts::apic::send_eoi();
}
