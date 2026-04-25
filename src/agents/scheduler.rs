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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const MAX_SCHEDULED: usize = 32;

#[derive(Clone)]
pub struct ScheduledRun {
    pub id: u32,
    pub agent_id: u32,
    pub prompt: Vec<u8>,
    pub run_at: u64,
    pub repeat_interval: u64,
    pub active: bool,
}

static SCHEDULED: Mutex<Vec<ScheduledRun>> = Mutex::new(Vec::new());
static NEXT_SCHED_ID: AtomicU32 = AtomicU32::new(1);

pub fn schedule_once(agent_id: u32, prompt: &[u8], run_at: u64) -> u32 {
    let id = NEXT_SCHED_ID.fetch_add(1, Ordering::Relaxed);
    let mut sched = SCHEDULED.lock();
    if sched.len() >= MAX_SCHEDULED {
        return 0;
    }
    sched.push(ScheduledRun {
        id,
        agent_id,
        prompt: prompt.to_vec(),
        run_at,
        repeat_interval: 0,
        active: true,
    });
    id
}

pub fn schedule_repeat(agent_id: u32, prompt: &[u8], interval_ms: u64) -> u32 {
    let id = NEXT_SCHED_ID.fetch_add(1, Ordering::Relaxed);
    let now = crate::time::timestamp_millis();
    let mut sched = SCHEDULED.lock();
    if sched.len() >= MAX_SCHEDULED {
        return 0;
    }
    sched.push(ScheduledRun {
        id,
        agent_id,
        prompt: prompt.to_vec(),
        run_at: now + interval_ms,
        repeat_interval: interval_ms,
        active: true,
    });
    id
}

pub fn cancel_schedule(id: u32) -> bool {
    let mut sched = SCHEDULED.lock();
    if let Some(s) = sched.iter_mut().find(|s| s.id == id) {
        s.active = false;
        true
    } else {
        false
    }
}

pub fn tick() {
    let now = crate::time::timestamp_millis();
    let mut sched = SCHEDULED.lock();
    for s in sched.iter_mut() {
        if !s.active {
            continue;
        }
        if now >= s.run_at {
            super::executor::run_agent(s.agent_id, &s.prompt);
            if s.repeat_interval > 0 {
                s.run_at = now + s.repeat_interval;
            } else {
                s.active = false;
            }
        }
    }
    sched.retain(|s| s.active || s.repeat_interval > 0);
}

pub fn list_scheduled(agent_id: u32) -> Vec<ScheduledRun> {
    SCHEDULED.lock().iter().filter(|s| s.agent_id == agent_id && s.active).cloned().collect()
}

pub fn active_count() -> usize {
    SCHEDULED.lock().iter().filter(|s| s.active).count()
}
