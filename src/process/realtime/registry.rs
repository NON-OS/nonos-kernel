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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::types::Deadline;

static DEADLINES: RwLock<BTreeMap<u32, Deadline>> = RwLock::new(BTreeMap::new());
static TOTAL_MISSES: AtomicU64 = AtomicU64::new(0);

pub fn set_deadline(pid: u32, dl: Deadline) -> Result<(), &'static str> {
    if pid == 0 {
        return Err("EINVAL");
    }
    if dl.tsc_deadline == 0 {
        return Err("EINVAL");
    }
    DEADLINES.write().insert(pid, dl);
    Ok(())
}

pub fn clear_deadline(pid: u32) -> bool {
    DEADLINES.write().remove(&pid).is_some()
}

#[inline]
pub fn get_deadline(pid: u32) -> Option<Deadline> {
    DEADLINES.read().get(&pid).copied()
}

pub fn list_deadlines() -> Vec<(u32, Deadline)> {
    let map = DEADLINES.read();
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

pub fn check_and_mark_deadlines(tsc_now: u64, tsc_freq_hz: u64) -> Vec<u32> {
    if tsc_freq_hz == 0 {
        return check_and_mark_deadlines_with_slack_ticks(tsc_now, 0);
    }
    let map = DEADLINES.read();
    let mut missed: Vec<u32> = Vec::new();
    for (pid, dl) in map.iter() {
        let slack_ticks = mul_div_u128(dl.slack_ns as u128, tsc_freq_hz as u128, 1_000_000_000u128) as u64;
        if tsc_now.saturating_sub(dl.tsc_deadline) > slack_ticks {
            missed.push(*pid);
        }
    }
    drop(map);
    if !missed.is_empty() {
        TOTAL_MISSES.fetch_add(missed.len() as u64, Ordering::Relaxed);
    }
    missed
}

pub fn check_and_mark_deadlines_with_slack_ticks(tsc_now: u64, slack_ticks: u64) -> Vec<u32> {
    let map = DEADLINES.read();
    let mut missed: Vec<u32> = Vec::new();
    for (pid, dl) in map.iter() {
        if tsc_now.saturating_sub(dl.tsc_deadline) > slack_ticks {
            missed.push(*pid);
        }
    }
    drop(map);
    if !missed.is_empty() {
        TOTAL_MISSES.fetch_add(missed.len() as u64, Ordering::Relaxed);
    }
    missed
}

#[inline]
pub fn stats_deadline_misses() -> u64 {
    TOTAL_MISSES.load(Ordering::Relaxed)
}

#[inline]
fn mul_div_u128(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 {
        return u128::MAX;
    }
    let prod = a.saturating_mul(b);
    prod / c
}
