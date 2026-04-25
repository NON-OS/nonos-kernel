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

use super::helpers::get_timestamp;
use core::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct CorruptionDetector {
    pub canary_base: u64,
    pub violations: AtomicUsize,
    pub last_check: AtomicUsize,
}

impl CorruptionDetector {
    pub(super) fn record_check(&self) {
        let timestamp = get_timestamp() as usize;
        self.last_check.store(timestamp, Ordering::Relaxed);
    }

    pub(super) fn last_check_time(&self) -> usize {
        self.last_check.load(Ordering::Relaxed)
    }
}
