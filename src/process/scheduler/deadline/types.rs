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

use core::sync::atomic::AtomicU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    NotInitialized,
    InvalidParameters,
    PeriodTooShort,
    InsufficientBandwidth,
}

#[derive(Debug, Clone)]
pub struct DeadlineStatsSnapshot {
    pub active_tasks: u64,
    pub total_bandwidth_percent: u64,
    pub deadline_misses: u64,
    pub activations: u64,
    pub runtime_consumed: u64,
    pub admission_rejections: u64,
    pub throttle_events: u64,
    pub replenishment_events: u64,
}

#[derive(Default)]
pub(super) struct DeadlineStats {
    pub deadline_misses: AtomicU64,
    pub activations: AtomicU64,
    pub runtime_consumed: AtomicU64,
    pub admission_rejections: AtomicU64,
    pub throttle_events: AtomicU64,
    pub replenishment_events: AtomicU64,
}

pub(super) const MAX_DL_BANDWIDTH: u64 = (95 << 20) / 100;
pub(super) const MIN_DL_PERIOD: u64 = 1_000_000;
