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

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::policy::IsolationPolicy;

pub struct IsolationState {
    pub capsule_name: &'static str,
    bytes_this_window: AtomicU64,
    window_start_ms: AtomicU64,
    dropped_messages: AtomicU64,
    enforced: bool,
    policy: IsolationPolicy,
    lock: Mutex<()>,
}

impl IsolationState {
    pub fn new(capsule_name: &'static str, policy: IsolationPolicy) -> Self {
        let now = crate::time::timestamp_millis();
        Self {
            capsule_name,
            bytes_this_window: AtomicU64::new(0),
            window_start_ms: AtomicU64::new(now),
            dropped_messages: AtomicU64::new(0),
            enforced: true,
            policy,
            lock: Mutex::new(()),
        }
    }

    pub fn charge_message(&self, size: usize) -> Result<(), &'static str> {
        if size > self.policy.max_msg_bytes {
            self.dropped_messages.fetch_add(1, Ordering::Relaxed);
            return Err("isolation: message too large");
        }

        let now = crate::time::timestamp_millis();
        if now
            .saturating_sub(self.window_start_ms.load(Ordering::Relaxed))
            >= 1_000
        {
            let _g = self.lock.lock();
            if now
                .saturating_sub(self.window_start_ms.load(Ordering::Relaxed))
                >= 1_000
            {
                self.window_start_ms.store(now, Ordering::Relaxed);
                self.bytes_this_window.store(0, Ordering::Relaxed);
            }
        }

        let used = self
            .bytes_this_window
            .fetch_add(size as u64, Ordering::Relaxed)
            + size as u64;
        if used > self.policy.max_bytes_per_sec && self.enforced {
            self.dropped_messages.fetch_add(1, Ordering::Relaxed);
            return Err("isolation: bandwidth exceeded");
        }

        Ok(())
    }

    pub fn check_inbox_capacity(&self) -> Result<(), &'static str> {
        let len = crate::ipc::nonos_inbox::len(self.capsule_name);
        if len >= self.policy.inbox_capacity {
            self.dropped_messages.fetch_add(1, Ordering::Relaxed);
            return Err("isolation: inbox full");
        }
        Ok(())
    }

    pub fn dropped(&self) -> u64 {
        self.dropped_messages.load(Ordering::Relaxed)
    }

    pub fn set_enforced(&mut self, on: bool) {
        self.enforced = on;
    }

    pub fn status(&self) -> String {
        let used = self.bytes_this_window.load(Ordering::Relaxed);
        let dropped = self.dropped_messages.load(Ordering::Relaxed);
        alloc::format!(
            "iso[capsule={} used={}/s limit={}/s dropped={}]",
            self.capsule_name, used, self.policy.max_bytes_per_sec, dropped
        )
    }
}
