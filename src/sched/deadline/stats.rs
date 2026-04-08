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

use core::sync::atomic::Ordering as AO;
use super::types::DeadlineStatsSnapshot;
use super::queue::get_scheduler;

pub fn get_stats() -> DeadlineStatsSnapshot {
    let s = get_scheduler().lock();
    DeadlineStatsSnapshot {
        active_tasks: s.active_count,
        total_bandwidth_percent: (s.total_bandwidth * 100) >> 20,
        deadline_misses: s.stats.deadline_misses.load(AO::Relaxed),
        activations: s.stats.activations.load(AO::Relaxed),
        runtime_consumed: s.stats.runtime_consumed.load(AO::Relaxed),
        admission_rejections: s.stats.admission_rejections.load(AO::Relaxed),
        throttle_events: s.stats.throttle_events.load(AO::Relaxed),
        replenishment_events: s.stats.replenishment_events.load(AO::Relaxed),
    }
}
