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

use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::RwLock;
use super::types::{ChannelState, Mode};

pub(super) static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(super) static CHANNELS: RwLock<[ChannelState; 3]> = RwLock::new([
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
]);

pub(super) static STATS_CALIBRATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static STATS_LAST_CALIBRATION: AtomicU64 = AtomicU64::new(0);
pub(super) static STATS_SPEAKER_BEEPS: AtomicU64 = AtomicU64::new(0);
pub(super) static STATS_ONESHOT_COMPLETED: AtomicU64 = AtomicU64::new(0);
