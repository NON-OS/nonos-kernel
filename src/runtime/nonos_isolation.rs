#![no_std]

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Isolation policy applied per-capsule
#[derive(Debug, Clone)]
pub struct IsolationPolicy {
    pub inbox_capacity: usize,
    pub max_msg_bytes: usize,
    pub max_bytes_per_sec: u64,
    pub heartbeat_interval_ms: u64,
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self {
            inbox_capacity: 1024,
            max_msg_bytes: 1 << 20,
            max_bytes_per_sec: 4 << 20,
            heartbeat_interval_ms: 2_000,
        }
    }
}

/// Runtime counters and rate-limiter state for a capsule
pub struct IsolationState {
    pub capsule_name: &'static str,
    bytes_this_window: AtomicU64,
    window_start_ms: AtomicU64,
    dropped_messages: AtomicU64,
    enforced: bool,
    policy: IsolationPolicy,
    // serialize window rollover
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

    /// Validate and charge a message of given size; returns Err if policy violation.
    pub fn charge_message(&self, size: usize) -> Result<(), &'static str> {
        if size > self.policy.max_msg_bytes {
            self.dropped_messages.fetch_add(1, Ordering::Relaxed);
            return Err("isolation: message too large");
        }

        let now = crate::time::timestamp_millis();
        // rollover window if >1s
        if now
            .saturating_sub(self.window_start_ms.load(Ordering::Relaxed))
            >= 1_000
        {
            let _g = self.lock.lock();
            // re-check under lock
            if now
                .saturating_sub(self.window_start_ms.load(Ordering::Relaxed))
                >= 1_000
            {
                self.window_start_ms.store(now, Ordering::Relaxed);
                self.bytes_this_window.store(0, Ordering::Relaxed);
            }
        }

        // charge
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

    /// Check inbox capacity for the capsule (using IPC inbox length)
    pub fn check_inbox_capacity(&self) -> Result<(), &'static str> {
        let len = crate::ipc::nonos_inbox::len(self.capsule_name);
        if len >= self.policy.inbox_capacity {
            self.dropped_messages.fetch_add(1, Ordering::Relaxed);
            return Err("isolation: inbox full");
        }
        Ok(())
    }

    /// Current dropped message counter
    pub fn dropped(&self) -> u64 {
        self.dropped_messages.load(Ordering::Relaxed)
    }

    /// Relax (disable) enforcement, for diagnostics
    pub fn set_enforced(&mut self, on: bool) {
        self.enforced = on;
    }

    /// Get a concise status string
    pub fn status(&self) -> String {
        let used = self.bytes_this_window.load(Ordering::Relaxed);
        let dropped = self.dropped_messages.load(Ordering::Relaxed);
        alloc::format!(
            "iso[capsule={} used={}/s limit={}/s dropped={}]",
            self.capsule_name, used, self.policy.max_bytes_per_sec, dropped
        )
    }
}
