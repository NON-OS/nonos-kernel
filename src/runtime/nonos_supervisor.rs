#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::runtime::nonos_capsule::CapsuleState;
use crate::runtime::nonos_zerostate::{get_capsule_by_name, start_capsule, stop_capsule};
use crate::syscall::capabilities::CapabilityToken;

/// Policy determining how a capsule is supervised.
#[derive(Debug, Clone)]
pub struct SupervisorPolicy {
    pub restart_on_degraded: bool,
    pub restart_on_stopped: bool,
    pub restart_cooldown_ms: u64,      // minimum time between restarts
    pub max_restarts_per_minute: u32,  // budget within a rolling minute
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            restart_on_degraded: true,
            restart_on_stopped: true,
            restart_cooldown_ms: 5_000,
            max_restarts_per_minute: 10,
        }
    }
}

#[derive(Debug, Clone)]
struct RestartWindow {
    window_start_ms: u64,
    count: u32,
    last_restart_ms: u64,
}

impl RestartWindow {
    fn new(now: u64) -> Self {
        Self { window_start_ms: now, count: 0, last_restart_ms: 0 }
    }
    fn can_restart(&mut self, now: u64, cooldown_ms: u64, max_per_minute: u32) -> bool {
        // Cooldown
        if self.last_restart_ms != 0 && now.saturating_sub(self.last_restart_ms) < cooldown_ms {
            return false;
        }
        // Window rotate (1 minute)
        if now.saturating_sub(self.window_start_ms) >= 60_000 {
            self.window_start_ms = now;
            self.count = 0;
        }
        if self.count >= max_per_minute { return false; }
        true
    }
    fn mark(&mut self, now: u64) {
        self.count = self.count.saturating_add(1);
        self.last_restart_ms = now;
    }
}

/// Supervisor maintains per-capsule state and policies.
struct SupReg {
    policies: BTreeMap<String, SupervisorPolicy>,
    restarts: BTreeMap<String, RestartWindow>,
    watched: Vec<String>,
}

impl SupReg {
    fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            restarts: BTreeMap::new(),
            watched: Vec::new(),
        }
    }
}

static SUP: RwLock<SupReg> = RwLock::new(SupReg::new());
static LAST_RUN_MS: AtomicU64 = AtomicU64::new(0);

/// Register a capsule name for supervision with a policy
pub fn register(name: &str, policy: SupervisorPolicy) {
    let now = crate::time::timestamp_millis();
    let mut s = SUP.write();
    if !s.policies.contains_key(name) {
        s.policies.insert(name.into(), policy);
    }
    if !s.restarts.contains_key(name) {
        s.restarts.insert(name.into(), RestartWindow::new(now));
    }
    if !s.watched.iter().any(|n| n == name) {
        s.watched.push(name.into());
    }
    crate::drivers::console::write_message(
        &alloc::format!("supervisor: watching '{}'", name)
    );
}

/// Remove a capsule from supervision (keeps counters for diagnostics)
pub fn unregister(name: &str) {
    let mut s = SUP.write();
    s.watched.retain(|n| n != name);
    s.policies.remove(name);
    // keep restarts to preserve history
}

/// One supervisor iteration: check health and restart if policy allows.
pub fn run_once(token: &CapabilityToken) {
    let now = crate::time::timestamp_millis();
    LAST_RUN_MS.store(now, Ordering::Relaxed);

    // Collect names to avoid holding the lock across restarts
    let names = {
        let s = SUP.read();
        s.watched.clone()
    };

    for name in names {
        let Some(cap) = get_capsule_by_name(&name) else { continue };
        let state = cap.health();

        let (policy, mut window) = {
            let s = SUP.read();
            let policy = match s.policies.get(&name) {
                Some(p) => p.clone(),
                None => SupervisorPolicy::default(),
            };
            let window = s.restarts.get(&name).cloned().unwrap_or(RestartWindow::new(now));
            (policy, window)
        };

        let need_restart = match state {
            CapsuleState::Degraded => policy.restart_on_degraded,
            CapsuleState::Stopped => policy.restart_on_stopped,
            CapsuleState::Running => false,
        };

        if need_restart && window.can_restart(now, policy.restart_cooldown_ms, policy.max_restarts_per_minute) {
            // Perform a clean stop then start
            let _ = stop_capsule(&name);
            if let Err(e) = start_capsule(&name, token) {
                crate::drivers::console::write_message(
                    &alloc::format!("supervisor: failed to restart '{}': {}", name, e)
                );
            } else {
                window.mark(now);
                let mut s = SUP.write();
                s.restarts.insert(name.clone(), window);
                crate::drivers::console::write_message(
                    &alloc::format!("supervisor: restarted '{}'", name)
                );
            }
        }
    }
}

/// Return restart counters for a capsule (count within current 1-minute window and last restart time)
pub fn restart_stats(name: &str) -> Option<(u32, u64)> {
    let s = SUP.read();
    s.restarts.get(name).map(|w| (w.count, w.last_restart_ms))
}
