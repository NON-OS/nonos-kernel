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

//! Per-vector IRQ slots, written in syscall context, read in hard
//! IRQ context. Each slot is purely atomic so the dispatcher does
//! not have to lock anything to deliver.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::interrupt::broker::BROKER_VEC_COUNT;

pub struct IrqSlot {
    pub active: AtomicBool,
    pub seq: AtomicU64,
    pub overflow: AtomicU64,
    pub grant_id: AtomicU64,
    pub gsi: AtomicU32,
}

impl IrqSlot {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            seq: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            grant_id: AtomicU64::new(0),
            gsi: AtomicU32::new(0),
        }
    }
}

const SLOT_INIT: IrqSlot = IrqSlot::new();
pub static SLOTS: [IrqSlot; BROKER_VEC_COUNT] = [SLOT_INIT; BROKER_VEC_COUNT];

static SLOT_BITMAP: AtomicU32 = AtomicU32::new(0);

pub fn try_alloc_slot() -> Option<usize> {
    loop {
        let cur = SLOT_BITMAP.load(Ordering::Acquire);
        let mut idx = None;
        for i in 0..BROKER_VEC_COUNT {
            if cur & (1u32 << i) == 0 {
                idx = Some(i);
                break;
            }
        }
        let i = idx?;
        let new = cur | (1u32 << i);
        if SLOT_BITMAP.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Some(i);
        }
    }
}

pub fn free_slot(idx: usize) {
    SLOT_BITMAP.fetch_and(!(1u32 << idx), Ordering::AcqRel);
}

pub fn activate(slot_idx: usize, grant_id: u64, gsi: u32) {
    let slot = &SLOTS[slot_idx];
    slot.grant_id.store(grant_id, Ordering::Relaxed);
    slot.gsi.store(gsi, Ordering::Relaxed);
    slot.seq.store(0, Ordering::Relaxed);
    slot.overflow.store(0, Ordering::Relaxed);
    slot.active.store(true, Ordering::Release);
}

pub fn deactivate(slot_idx: usize) {
    let slot = &SLOTS[slot_idx];
    slot.active.store(false, Ordering::Release);
    slot.grant_id.store(0, Ordering::Relaxed);
    slot.gsi.store(0, Ordering::Relaxed);
}

pub fn read_counters(slot_idx: usize) -> (u64, u64) {
    let slot = &SLOTS[slot_idx];
    (slot.seq.load(Ordering::Acquire), slot.overflow.load(Ordering::Acquire))
}
