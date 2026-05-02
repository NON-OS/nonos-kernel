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
use core::sync::atomic::{AtomicU64, Ordering};

use super::core::SignalState;
use crate::process::signal::sigaction::Sigaction;

impl SignalState {
    pub fn clone_for_fork(&self) -> Self {
        Self {
            pending: AtomicU64::new(0),
            blocked: AtomicU64::new(self.blocked.load(Ordering::Relaxed)),
            actions: core::array::from_fn(|i| self.actions[i].clone()),
            queue: VecDeque::new(),
            trampoline: AtomicU64::new(self.trampoline.load(Ordering::Relaxed)),
            saved_mask: None,
        }
    }

    pub fn reset_for_exec(&mut self) {
        self.pending.store(0, Ordering::Release);
        self.queue.clear();
        self.trampoline.store(0, Ordering::Release);
        self.saved_mask = None;
        for action in &mut self.actions {
            if action.is_handler() {
                *action = Sigaction::default();
            }
        }
    }
}
