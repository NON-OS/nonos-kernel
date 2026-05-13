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

// 128 simultaneous PLIC bindings. PLIC source 0 is reserved by spec,
// so `source == 0` doubles as the free marker.
pub(super) const MAX_GRANTS: usize = 128;

#[repr(C, align(64))]
pub(super) struct Entry {
    pub(super) source: AtomicU32,
    pub(super) pid: AtomicU32,
    pub(super) grant_id: AtomicU64,
    pub(super) device_id: AtomicU64,
    pub(super) claim_epoch: AtomicU64,
    pub(super) pending: AtomicU64,
    pub(super) overflow: AtomicU64,
}

pub(super) static SLOTS: [Entry; MAX_GRANTS] = [const {
    Entry {
        source: AtomicU32::new(0),
        pid: AtomicU32::new(0),
        grant_id: AtomicU64::new(0),
        device_id: AtomicU64::new(0),
        claim_epoch: AtomicU64::new(0),
        pending: AtomicU64::new(0),
        overflow: AtomicU64::new(0),
    }
}; MAX_GRANTS];

static NEXT_GRANT_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn alloc(source: u32, pid: u32, device_id: u64, claim_epoch: u64) -> Option<(usize, u64)> {
    if find_by_source(source).is_some() {
        return None;
    }
    for i in 0..MAX_GRANTS {
        let e = &SLOTS[i];
        if e.source
            .compare_exchange(0, source, Ordering::AcqRel, Ordering::Acquire)
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

pub(super) fn find_by_source(source: u32) -> Option<&'static Entry> {
    if source == 0 {
        return None;
    }
    SLOTS.iter().find(|e| e.source.load(Ordering::Acquire) == source)
}

pub(super) fn find_by_grant(grant_id: u64) -> Option<&'static Entry> {
    if grant_id == 0 {
        return None;
    }
    SLOTS.iter().find(|e| {
        e.source.load(Ordering::Acquire) != 0 && e.grant_id.load(Ordering::Acquire) == grant_id
    })
}
