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

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use super::snapshot::Snapshot;

struct RuntimeStats {
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
    alloc::format!(
        "rt_stats: start={} stop={} restart={} hb={}",
        s.starts, s.stops, s.restarts, s.heartbeats
    )
}
