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

use super::super::service_list::CORE_SERVICES;
use super::super::spawner::cap_for_service;
use crate::kernel_core::spawn_isolated_service;
use crate::process::core::table::PROCESS_TABLE;
use crate::process::core::types::ProcessState;
use alloc::collections::BTreeMap;
use spin::Mutex;

const MAX_RESTART_ATTEMPTS: u32 = 5;
const RESTART_BACKOFF_BASE_MS: u64 = 1000;

static RESTART_STATE: Mutex<BTreeMap<&'static str, RestartInfo>> = Mutex::new(BTreeMap::new());

struct RestartInfo {
    attempts: u32,
    last_restart_ms: u64,
}

pub(super) fn supervise_services() {
    let now = crate::time::timestamp_millis();
    for &name in CORE_SERVICES {
        if should_restart_service(name, now) {
            restart_service(name, now);
        }
    }
}

fn should_restart_service(name: &'static str, now: u64) -> bool {
    let procs = PROCESS_TABLE.get_all_processes();
    let found = procs.iter().find(|p| *p.name.lock() == name);
    if let Some(pcb) = found {
        let state = *pcb.state.lock();
        if matches!(state, ProcessState::Terminated(_) | ProcessState::Zombie(_)) {
            let mut state_map = RESTART_STATE.lock();
            let info =
                state_map.entry(name).or_insert(RestartInfo { attempts: 0, last_restart_ms: 0 });
            if info.attempts >= MAX_RESTART_ATTEMPTS {
                return false;
            }
            let backoff = RESTART_BACKOFF_BASE_MS * (1 << info.attempts.min(4));
            return now >= info.last_restart_ms + backoff;
        }
    } else {
        return true;
    }
    false
}

fn restart_service(name: &'static str, now: u64) {
    crate::sys::serial::print(b"[INIT] Restarting service: ");
    crate::sys::serial::println(name.as_bytes());
    let caps = cap_for_service(name);
    match spawn_isolated_service(name, caps) {
        Ok(_) => {
            let mut state_map = RESTART_STATE.lock();
            if let Some(info) = state_map.get_mut(name) {
                info.attempts += 1;
                info.last_restart_ms = now;
            }
            crate::sys::serial::print(b"[INIT] Service restarted: ");
            crate::sys::serial::println(name.as_bytes());
        }
        Err(_) => {
            crate::sys::serial::print(b"[INIT] Failed to restart: ");
            crate::sys::serial::println(name.as_bytes());
        }
    }
}
