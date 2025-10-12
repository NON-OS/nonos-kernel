#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// Real-time deadline descriptor for process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    pub tsc_deadline: u64,
    pub slack_ns: u64,
}

/// Global deadline registry
static DEADLINES: RwLock<BTreeMap<u32, Deadline>> = RwLock::new(BTreeMap::new());
static TOTAL_MISSES: AtomicU64 = AtomicU64::new(0);

/// Install or replace a deadline for a pid.
pub fn set_deadline(pid: u32, dl: Deadline) -> Result<(), &'static str> {
    if pid == 0 { return Err("EINVAL"); }
    if dl.tsc_deadline == 0 { return Err("EINVAL"); }
    DEADLINES.write().insert(pid, dl);
    Ok(())
}

/// Remove a deadline for a pid. Returns true if it existed.
pub fn clear_deadline(pid: u32) -> bool {
    DEADLINES.write().remove(&pid).is_some()
}

/// Fetch the current deadline for a pid, if present.
#[inline]
pub fn get_deadline(pid: u32) -> Option<Deadline> {
    DEADLINES.read().get(&pid).copied()
}

/// Snapshot all active (pid, deadline) entries.
pub fn list_deadlines() -> Vec<(u32, Deadline)> {
    let map = DEADLINES.read();
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

/// Evaluate deadlines against TSC value and return the list of PIDs.
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

/// Variant when slack is already in ticks.
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

/// Aggregate count of missed deadlines since boot.
#[inline]
pub fn stats_deadline_misses() -> u64 {
    TOTAL_MISSES.load(Ordering::Relaxed)
}

/// Compute floor(a*b/c) in 128-bit to avoid overflow.
#[inline]
fn mul_div_u128(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 { return u128::MAX; }
    let prod = a.saturating_mul(b);
    prod / c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_clear() {
        let pid = 42;
        assert!(get_deadline(pid).is_none());
        set_deadline(pid, Deadline { tsc_deadline: 1_000_000, slack_ns: 0 }).unwrap();
        let d = get_deadline(pid).unwrap();
        assert_eq!(d.tsc_deadline, 1_000_000);
        assert!(clear_deadline(pid));
        assert!(get_deadline(pid).is_none());
        assert!(!clear_deadline(pid));
    }

    #[test]
    fn list_and_check_with_freq() {
        set_deadline(1, Deadline { tsc_deadline: 1_000_000, slack_ns: 0 }).unwrap();
        set_deadline(2, Deadline { tsc_deadline: 9_000_000, slack_ns: 0 }).unwrap();

        let missed = check_and_mark_deadlines(5_000_000, 1_000_000_000);
        assert_eq!(missed, alloc::vec![1]);
        assert_eq!(stats_deadline_misses(), 1);

        let missed2 = check_and_mark_deadlines(10_000_000, 1_000_000_000);
        assert!(missed2.contains(&1) && missed2.contains(&2));
        assert_eq!(stats_deadline_misses(), 1 + missed2.len() as u64);
    }

    #[test]
    fn slack_conversion() {
        set_deadline(10, Deadline { tsc_deadline: 1_000_000, slack_ns: 100 }).unwrap();
        let m1 = check_and_mark_deadlines(1_000_050, 1_000_000_000);
        assert!(m1.is_empty());
        let m2 = check_and_mark_deadlines(1_000_200, 1_000_000_000);
        assert_eq!(m2, alloc::vec![10]);
    }

    #[test]
    fn invalid_inputs() {
        assert!(set_deadline(0, Deadline { tsc_deadline: 1, slack_ns: 0 }).is_err());
        assert!(set_deadline(1, Deadline { tsc_deadline: 0, slack_ns: 0 }).is_err());
    }
}
