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

use super::types::{IoEvent, Iocb};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static CONTEXT_ID: AtomicU64 = AtomicU64::new(1);
static CONTEXTS: Mutex<BTreeMap<u64, AioContext>> = Mutex::new(BTreeMap::new());

pub struct AioContext {
    pub id: u64,
    pub max_events: u32,
    pub pending: VecDeque<Iocb>,
    pub completed: VecDeque<IoEvent>,
}

impl AioContext {
    pub fn new(max_events: u32) -> Self {
        Self {
            id: CONTEXT_ID.fetch_add(1, Ordering::SeqCst),
            max_events,
            pending: VecDeque::new(),
            completed: VecDeque::new(),
        }
    }

    pub fn create(max_events: u32) -> Result<u64, i32> {
        if max_events == 0 || max_events > 65536 {
            return Err(22);
        }
        let ctx = Self::new(max_events);
        let id = ctx.id;
        CONTEXTS.lock().insert(id, ctx);
        Ok(id)
    }

    pub fn destroy(id: u64) -> Result<(), i32> {
        CONTEXTS.lock().remove(&id).map(|_| ()).ok_or(22)
    }

    pub fn submit(id: u64, iocbs: Vec<Iocb>) -> Result<i32, i32> {
        let mut contexts = CONTEXTS.lock();
        let ctx = contexts.get_mut(&id).ok_or(22)?;
        let count = iocbs.len() as i32;
        for iocb in iocbs {
            let event = Self::execute_iocb(&iocb);
            ctx.completed.push_back(event);
        }
        Ok(count)
    }

    pub fn getevents(id: u64, min_nr: i64, max_nr: i64) -> Result<Vec<IoEvent>, i32> {
        let mut contexts = CONTEXTS.lock();
        let ctx = contexts.get_mut(&id).ok_or(22)?;
        let mut events = Vec::new();
        let max = max_nr.min(ctx.completed.len() as i64) as usize;
        for _ in 0..max {
            if let Some(event) = ctx.completed.pop_front() {
                events.push(event);
            }
        }
        if (events.len() as i64) < min_nr && min_nr > 0 {
            for event in events.drain(..) {
                ctx.completed.push_front(event);
            }
            return Err(11);
        }
        Ok(events)
    }

    fn execute_iocb(iocb: &Iocb) -> IoEvent {
        let res = match iocb.opcode() {
            Some(super::types::AioOpcode::Pread) => Self::do_pread(iocb),
            Some(super::types::AioOpcode::Pwrite) => Self::do_pwrite(iocb),
            Some(super::types::AioOpcode::Fsync) => {
                crate::syscall::extended::handle_fsync(iocb.aio_fildes as i32).value
            }
            Some(super::types::AioOpcode::Noop) => 0,
            _ => -22,
        };
        IoEvent::new(iocb.aio_data, iocb as *const _ as u64, res)
    }

    fn do_pread(iocb: &Iocb) -> i64 {
        crate::syscall::extended::handle_pread64(
            iocb.aio_fildes as i32,
            iocb.aio_buf,
            iocb.aio_nbytes,
            iocb.aio_offset,
        )
        .value
    }

    fn do_pwrite(iocb: &Iocb) -> i64 {
        crate::syscall::extended::handle_pwrite64(
            iocb.aio_fildes as i32,
            iocb.aio_buf,
            iocb.aio_nbytes,
            iocb.aio_offset,
        )
        .value
    }

    pub fn cancel(id: u64, data: u64) -> Result<IoEvent, i32> {
        let mut contexts = CONTEXTS.lock();
        let ctx = contexts.get_mut(&id).ok_or(22)?;
        let idx = ctx.pending.iter().position(|iocb| iocb.aio_data == data).ok_or(11)?;
        let iocb = ctx.pending.remove(idx).ok_or(11)?;
        Ok(IoEvent::error(iocb.aio_data, 0, 125))
    }

    pub fn cancel_all(id: u64) -> Result<usize, i32> {
        let mut contexts = CONTEXTS.lock();
        let ctx = contexts.get_mut(&id).ok_or(22)?;
        let count = ctx.pending.len();
        for iocb in ctx.pending.drain(..) {
            ctx.completed.push_back(IoEvent::error(iocb.aio_data, 0, 125));
        }
        Ok(count)
    }

    pub fn cancel_by_fd(id: u64, fd: i32) -> Result<usize, i32> {
        let mut contexts = CONTEXTS.lock();
        let ctx = contexts.get_mut(&id).ok_or(22)?;
        let mut cancelled = 0;
        let mut remaining = VecDeque::new();
        for iocb in ctx.pending.drain(..) {
            if iocb.aio_fildes as i32 == fd {
                ctx.completed.push_back(IoEvent::error(iocb.aio_data, 0, 125));
                cancelled += 1;
            } else {
                remaining.push_back(iocb);
            }
        }
        ctx.pending = remaining;
        Ok(cancelled)
    }

    pub fn has_pending(id: u64, data: u64) -> bool {
        let contexts = CONTEXTS.lock();
        contexts.get(&id).map(|ctx| ctx.pending.iter().any(|i| i.aio_data == data)).unwrap_or(false)
    }

    pub fn pending_count(id: u64) -> usize {
        CONTEXTS.lock().get(&id).map(|ctx| ctx.pending.len()).unwrap_or(0)
    }

    pub fn completed_count(id: u64) -> usize {
        CONTEXTS.lock().get(&id).map(|ctx| ctx.completed.len()).unwrap_or(0)
    }

    pub fn context_exists(id: u64) -> bool {
        CONTEXTS.lock().contains_key(&id)
    }
}
