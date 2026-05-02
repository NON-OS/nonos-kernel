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

use core::sync::atomic::Ordering;

use super::core::SignalState;
use crate::process::signal::error::SignalError;
use crate::process::signal::queued::QueuedSignal;
use crate::process::signal::siginfo::SigInfo;

const MAX_QUEUED_SIGNALS: usize = 1024;

impl SignalState {
    pub fn queue_signal(&mut self, signo: u8, info: SigInfo) -> Result<(), SignalError> {
        if self.queue.len() >= MAX_QUEUED_SIGNALS {
            return Err(SignalError::QueueFull);
        }
        self.queue.push_back(QueuedSignal::new(signo, info));
        self.set_pending(signo);
        Ok(())
    }

    pub fn dequeue_signal(&mut self, signo: u8) -> Option<SigInfo> {
        let pos = self.queue.iter().position(|q| q.signo == signo)?;
        let queued = self.queue.remove(pos)?;
        if !self.queue.iter().any(|q| q.signo == signo) {
            self.clear_pending(signo);
        }
        Some(queued.info)
    }

    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }

    pub fn queued_count_for(&self, signo: u8) -> usize {
        self.queue.iter().filter(|q| q.signo == signo).count()
    }

    pub fn clear_all_pending(&mut self) {
        self.pending.store(0, Ordering::Release);
        self.queue.clear();
    }
}
