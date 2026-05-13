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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// 128 simultaneous GIC bindings per kernel. Cheap linear scan on the
// trap path; the trap-time hot path is `find_by_intid`.
pub(super) const MAX_GRANTS: usize = 128;

// `intid == 0` marks a free slot. SGIs use intid 0..15 so we are not
// shadowing a real binding — SGIs are kernel-owned and the bind path
// rejects intid < 32.
#[repr(C, align(64))]
pub(super) struct Entry {
    pub(super) intid: AtomicU32,
    pub(super) pid: AtomicU32,
    pub(super) grant_id: AtomicU64,
    pub(super) device_id: AtomicU64,
    pub(super) claim_epoch: AtomicU64,
    pub(super) pending: AtomicU64,
    pub(super) overflow: AtomicU64,
}

pub(super) static SLOTS: [Entry; MAX_GRANTS] = [const {
    Entry {
        intid: AtomicU32::new(0),
        pid: AtomicU32::new(0),
        grant_id: AtomicU64::new(0),
        device_id: AtomicU64::new(0),
        claim_epoch: AtomicU64::new(0),
        pending: AtomicU64::new(0),
        overflow: AtomicU64::new(0),
    }
}; MAX_GRANTS];

static NEXT_GRANT_ID: AtomicU64 = AtomicU64::new(1);

// CAS-claim the first free slot for `intid`. Returns the slot index
// and a fresh grant id, or None if the table is full or the intid is
// already bound.
pub(super) fn alloc(intid: u32, pid: u32, device_id: u64, claim_epoch: u64) -> Option<(usize, u64)> {
    if find_by_intid(intid).is_some() {
        return None;
    }
    for i in 0..MAX_GRANTS {
        let e = &SLOTS[i];
        if e.intid
            .compare_exchange(0, intid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let id = NEXT_GRANT_ID.fetch_add(1, Ordering::Relaxed);
            e.pid.store(pid, Ordering::Release);
            e.grant_id.store(id, Ordering::Release);
            e.device_id.store(device_id, Ordering::Release);
            e.claim_epoch.store(claim_epoch, Ordering::Release);
            e.pending.store(0, Ordering::Release);
            e.overflow.store(0, Ordering::Release);
            return Some((i, id));
        }
    }
    None
}

pub(super) fn find_by_intid(intid: u32) -> Option<&'static Entry> {
    if intid == 0 {
        return None;
    }
    SLOTS.iter().find(|e| e.intid.load(Ordering::Acquire) == intid)
}

pub(super) fn find_by_grant(grant_id: u64) -> Option<&'static Entry> {
    if grant_id == 0 {
        return None;
    }
    SLOTS.iter().find(|e| {
        e.intid.load(Ordering::Acquire) != 0 && e.grant_id.load(Ordering::Acquire) == grant_id
    })
}

// Mark the slot free. Caller must have already unregistered the GIC
// handler before this so no trampoline can race the slot's reuse.
pub(super) fn free(e: &'static Entry) {
    e.intid.store(0, Ordering::Release);
}
