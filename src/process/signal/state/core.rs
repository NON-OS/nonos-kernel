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

use alloc::collections::VecDeque;
use core::sync::atomic::AtomicU64;

use crate::process::signal::constants::SIG_COUNT;
use crate::process::signal::queued::QueuedSignal;
use crate::process::signal::sigaction::Sigaction;

pub struct SignalState {
    pub(super) pending: AtomicU64,
    pub(super) blocked: AtomicU64,
    pub(super) actions: [Sigaction; SIG_COUNT],
    pub(super) queue: VecDeque<QueuedSignal>,
    pub(super) trampoline: AtomicU64,
    pub(super) saved_mask: Option<u64>,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            actions: core::array::from_fn(|_| Sigaction::default()),
            queue: VecDeque::new(),
            trampoline: AtomicU64::new(0),
            saved_mask: None,
        }
    }
}

impl core::fmt::Debug for SignalState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::sync::atomic::Ordering;
        f.debug_struct("SignalState")
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .field("blocked", &self.blocked.load(Ordering::Relaxed))
            .field("queued", &self.queue.len())
            .finish()
    }
}

#[inline]
pub(super) fn mask_of(signo: u8) -> u64 {
    if signo == 0 || signo as usize >= SIG_COUNT {
        0
    } else {
        1u64 << (signo as u64)
    }
}
