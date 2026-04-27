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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(crate) const MAX_RUNNING: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct RunningApp {
    pub app_id: u32,
    pub start_time: u64,
    pub active: bool,
}

static RUNNING: Mutex<[RunningApp; MAX_RUNNING]> =
    Mutex::new([RunningApp { app_id: 0, start_time: 0, active: false }; MAX_RUNNING]);
static RUNNING_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn run_app(app_id: u32) -> bool {
    if is_running(app_id) {
        return true;
    }
    let mut running = RUNNING.lock();
    for r in running.iter_mut() {
        if !r.active {
            r.app_id = app_id;
            r.start_time = crate::time::timestamp_millis();
            r.active = true;
            RUNNING_COUNT.fetch_add(1, Ordering::Relaxed);
            super::registry::update_app_stats(app_id, r.start_time / 1000);
            return true;
        }
    }
    false
}

pub fn stop_app(app_id: u32) -> bool {
    let mut running = RUNNING.lock();
    for r in running.iter_mut() {
        if r.active && r.app_id == app_id {
            r.active = false;
            RUNNING_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

pub fn is_running(app_id: u32) -> bool {
    let running = RUNNING.lock();
    running.iter().any(|r| r.active && r.app_id == app_id)
}

pub fn running_count() -> u32 {
    RUNNING_COUNT.load(Ordering::Relaxed)
}

pub fn list_running() -> alloc::vec::Vec<u32> {
    let running = RUNNING.lock();
    running.iter().filter(|r| r.active).map(|r| r.app_id).collect()
}
