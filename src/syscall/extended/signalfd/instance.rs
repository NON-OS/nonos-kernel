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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::syscall::signals::types::{SigSet, PendingSignal};
use super::types::SFD_NONBLOCK;

pub const MAX_SIGNALFD_INSTANCES: usize = 256;

pub struct SignalfdInstance {
    pub id: u32,
    pub mask: SigSet,
    pub flags: i32,
    pub owner_pid: u32,
    pub queue: Vec<PendingSignal>,
}

impl SignalfdInstance {
    pub fn new(id: u32, mask: SigSet, flags: i32, owner_pid: u32) -> Self {
        Self {
            id,
            mask,
            flags,
            owner_pid,
            queue: Vec::new(),
        }
    }

    pub fn is_nonblock(&self) -> bool {
        (self.flags & SFD_NONBLOCK) != 0
    }

    pub fn set_mask(&mut self, mask: SigSet) {
        self.mask = mask;
    }

    pub fn matches(&self, signo: u32) -> bool {
        self.mask.contains(signo)
    }

    pub fn queue_signal(&mut self, signal: PendingSignal) {
        if self.queue.len() < 256 {
            self.queue.push(signal);
        }
    }

    pub fn dequeue_signal(&mut self) -> Option<PendingSignal> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.queue.remove(0))
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }
}

pub static SIGNALFD_INSTANCES: Mutex<BTreeMap<u32, SignalfdInstance>> = Mutex::new(BTreeMap::new());
pub static NEXT_SIGNALFD_ID: AtomicU32 = AtomicU32::new(1);

pub static FD_TO_SIGNALFD: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static NEXT_FD: AtomicU32 = AtomicU32::new(6000);

pub fn allocate_signalfd_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32
}

pub fn current_pid() -> u32 {
    crate::process::current_pid().unwrap_or(1)
}
