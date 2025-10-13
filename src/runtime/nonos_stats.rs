#![no_std]

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

/// Runtime-level statistics and telemetry.
pub struct RuntimeStats {
    starts: AtomicU64,
    stops: AtomicU64,
    restarts: AtomicU64,
    heartbeats: AtomicU64,
}

static STATS: RuntimeStats = RuntimeStats {
    starts: AtomicU64::new(0),
    stops: AtomicU64::new(0),
    restarts: AtomicU64::new(0),
    heartbeats: AtomicU64::new(0),
};

pub fn mark_start() {
    STATS.starts.fetch_add(1, Ordering::Relaxed);
}
pub fn mark_stop() {
    STATS.stops.fetch_add(1, Ordering::Relaxed);
}
pub fn mark_restart() {
    STATS.restarts.fetch_add(1, Ordering::Relaxed);
}
pub fn mark_heartbeat() {
    STATS.heartbeats.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub starts: u64,
    pub stops: u64,
    pub restarts: u64,
    pub heartbeats: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        starts: STATS.starts.load(Ordering::Relaxed),
        stops: STATS.stops.load(Ordering::Relaxed),
        restarts: STATS.restarts.load(Ordering::Relaxed),
        heartbeats: STATS.heartbeats.load(Ordering::Relaxed),
    }
}

pub fn as_string() -> String {
    let s = snapshot();
    alloc::format!("rt_stats: start={} stop={} restart={} hb={}", s.starts, s.stops, s.restarts, s.heartbeats)
}
