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

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::RwLock;
use crate::capsule::CapsuleId;
use super::types::{CapsuleMsg, MsgError, MAX_QUEUE_SIZE};

struct QueueStore {
    queues: BTreeMap<CapsuleId, VecDeque<CapsuleMsg>>,
    pending: u64,
}

static STORE: RwLock<Option<QueueStore>> = RwLock::new(None);

pub fn init_queues() { *STORE.write() = Some(QueueStore { queues: BTreeMap::new(), pending: 0 }); }

pub fn create_queue(id: CapsuleId) {
    if let Some(s) = STORE.write().as_mut() { s.queues.entry(id).or_insert_with(VecDeque::new); }
}

pub fn destroy_queue(id: CapsuleId) {
    if let Some(s) = STORE.write().as_mut() {
        if let Some(q) = s.queues.remove(&id) { s.pending = s.pending.saturating_sub(q.len() as u64); }
    }
}

pub fn enqueue(id: CapsuleId, msg: CapsuleMsg) -> Result<(), MsgError> {
    let mut guard = STORE.write();
    let s = guard.as_mut().ok_or(MsgError::NotFound)?;
    let q = s.queues.get_mut(&id).ok_or(MsgError::InvalidDest)?;
    if q.len() >= MAX_QUEUE_SIZE { return Err(MsgError::QueueFull); }
    q.push_back(msg);
    s.pending += 1;
    Ok(())
}

pub fn dequeue(id: CapsuleId) -> Result<CapsuleMsg, MsgError> {
    let mut guard = STORE.write();
    let s = guard.as_mut().ok_or(MsgError::NotFound)?;
    let q = s.queues.get_mut(&id).ok_or(MsgError::InvalidDest)?;
    let msg = q.pop_front().ok_or(MsgError::QueueEmpty)?;
    s.pending = s.pending.saturating_sub(1);
    Ok(msg)
}

pub fn peek(id: CapsuleId) -> Option<CapsuleMsg> {
    STORE.read().as_ref()?.queues.get(&id)?.front().cloned()
}

pub fn queue_len(id: CapsuleId) -> usize {
    STORE.read().as_ref().and_then(|s| s.queues.get(&id).map(|q| q.len())).unwrap_or(0)
}

pub fn total_pending() -> u64 {
    STORE.read().as_ref().map(|s| s.pending).unwrap_or(0)
}
