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


//! Lock-free record of the NMIs that reach the hardware-cause path, so a
//! later context that may lock and allocate can report what the NMI could not.

use core::sync::atomic::{AtomicU64, Ordering};

use super::nmi_source::NmiSource;

static COUNTS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static LAST_RIP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct NmiCounts {
    pub memory_parity: u64,
    pub io_channel_check: u64,
    pub watchdog: u64,
    pub unknown: u64,
    pub last_rip: u64,
}

const fn slot(source: NmiSource) -> usize {
    match source {
        NmiSource::MemoryParity => 0,
        NmiSource::IoChannelCheck => 1,
        NmiSource::Watchdog => 2,
        NmiSource::Unknown => 3,
    }
}

pub(super) fn record(source: NmiSource, rip: u64) {
    COUNTS[slot(source)].fetch_add(1, Ordering::Relaxed);
    LAST_RIP.store(rip, Ordering::Relaxed);
}

pub fn nmi_counts() -> NmiCounts {
    let count = |source| COUNTS[slot(source)].load(Ordering::Relaxed);
    NmiCounts {
        memory_parity: count(NmiSource::MemoryParity),
        io_channel_check: count(NmiSource::IoChannelCheck),
        watchdog: count(NmiSource::Watchdog),
        unknown: count(NmiSource::Unknown),
        last_rip: LAST_RIP.load(Ordering::Relaxed),
    }
}
