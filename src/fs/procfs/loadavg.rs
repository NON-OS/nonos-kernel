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

use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

static LOAD_1: AtomicU64 = AtomicU64::new(0);
static LOAD_5: AtomicU64 = AtomicU64::new(0);
static LOAD_15: AtomicU64 = AtomicU64::new(0);

pub fn read_loadavg() -> String {
    let (load1, load5, load15) = get_load_averages();
    let (running, total) = get_process_counts();
    let last_pid = crate::process::last_pid();
    format!("{:.2} {:.2} {:.2} {}/{} {}\n", load1, load5, load15, running, total, last_pid)
}

pub fn get_load_averages() -> (f64, f64, f64) {
    let l1 = LOAD_1.load(Ordering::Relaxed) as f64 / 65536.0;
    let l5 = LOAD_5.load(Ordering::Relaxed) as f64 / 65536.0;
    let l15 = LOAD_15.load(Ordering::Relaxed) as f64 / 65536.0;
    (l1, l5, l15)
}

fn get_process_counts() -> (usize, usize) {
    let stats = crate::sched::get_scheduler_stats();
    (stats.running_count, stats.total_count)
}

pub fn update_load_averages() {
    let running = crate::sched::get_runnable_count() as u64;
    let exp_1 = 1884;
    let exp_5 = 2014;
    let exp_15 = 2037;
    let old1 = LOAD_1.load(Ordering::Relaxed);
    let old5 = LOAD_5.load(Ordering::Relaxed);
    let old15 = LOAD_15.load(Ordering::Relaxed);
    let new1 = calc_load(old1, exp_1, running);
    let new5 = calc_load(old5, exp_5, running);
    let new15 = calc_load(old15, exp_15, running);
    LOAD_1.store(new1, Ordering::Relaxed);
    LOAD_5.store(new5, Ordering::Relaxed);
    LOAD_15.store(new15, Ordering::Relaxed);
}

fn calc_load(old: u64, exp: u64, active: u64) -> u64 {
    let load = old * exp + active * (2048 - exp);
    (load + 1024) >> 11
}
