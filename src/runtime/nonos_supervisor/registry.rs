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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{RwLock, Once};

use crate::runtime::nonos_capsule::CapsuleState;
use crate::runtime::nonos_zerostate::{get_capsule_by_name, start_capsule, stop_capsule};
use crate::syscall::capabilities::CapabilityToken;

use super::policy::SupervisorPolicy;
use super::restart_window::RestartWindow;

struct SupervisorRegistry {
    policies: BTreeMap<String, SupervisorPolicy>,
    restarts: BTreeMap<String, RestartWindow>,
    watched: Vec<String>,
}

impl SupervisorRegistry {
    fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            restarts: BTreeMap::new(),
            watched: Vec::new(),
        }
    }
}

static SUPERVISOR: Once<RwLock<SupervisorRegistry>> = Once::new();
static LAST_RUN_MS: AtomicU64 = AtomicU64::new(0);

fn get_supervisor() -> &'static RwLock<SupervisorRegistry> {
    SUPERVISOR.call_once(|| RwLock::new(SupervisorRegistry::new()))
}

pub fn register(name: &str, policy: SupervisorPolicy) {
    let now = crate::time::timestamp_millis();
    let mut s = get_supervisor().write();
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

pub fn unregister(name: &str) {
    let mut s = get_supervisor().write();
    s.watched.retain(|n| n != name);
    s.policies.remove(name);
}

pub fn run_once(token: &CapabilityToken) {
    let now = crate::time::timestamp_millis();
    LAST_RUN_MS.store(now, Ordering::Relaxed);

    let names = {
        let s = get_supervisor().read();
        s.watched.clone()
    };

    for name in names {
        let Some(cap) = get_capsule_by_name(&name) else { continue };
        let state = cap.health();

        let (policy, mut window) = {
            let s = get_supervisor().read();
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
            let _ = stop_capsule(&name);
            if let Err(e) = start_capsule(&name, token) {
                crate::drivers::console::write_message(
                    &alloc::format!("supervisor: failed to restart '{}': {}", name, e)
                );
            } else {
                window.mark(now);
                let mut s = get_supervisor().write();
                s.restarts.insert(name.clone(), window);
                crate::drivers::console::write_message(
                    &alloc::format!("supervisor: restarted '{}'", name)
                );
            }
        }
    }
}

pub fn restart_stats(name: &str) -> Option<(u32, u64)> {
    let s = get_supervisor().read();
    s.restarts.get(name).map(|w| (w.count, w.last_restart_ms))
}
