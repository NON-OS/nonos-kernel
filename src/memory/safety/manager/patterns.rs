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

use super::super::constants::*;
use super::super::types::*;
use super::state::MemorySafety;
use alloc::vec::Vec;

impl MemorySafety {
    pub(super) fn analyze_patterns(&self) -> Vec<MemoryAnomaly> {
        let history = self.access_history.read();
        let mut anomalies = Vec::new();
        if history.len() < 2 {
            return anomalies;
        }

        for window in history.windows(OVERFLOW_DETECTION_WINDOW) {
            if self.detect_buffer_overflow_pattern(window) {
                anomalies.push(MemoryAnomaly::BufferOverflow {
                    start_addr: window[0].addr,
                    pattern_length: window.len(),
                });
            }
        }

        for window in history.windows(UAF_DETECTION_WINDOW) {
            if self.detect_use_after_free_pattern(window) {
                anomalies
                    .push(MemoryAnomaly::UseAfterFree { addr: window[0].addr, confidence: 0.8 });
            }
        }
        anomalies
    }

    pub(super) fn detect_buffer_overflow_pattern(&self, window: &[AccessPattern]) -> bool {
        let mut sequential_writes = 0;
        let mut last_addr = 0;

        for pattern in window {
            if pattern.access_type == AccessType::Write {
                if pattern.addr > last_addr && pattern.addr - last_addr < SEQUENTIAL_WRITE_GAP {
                    sequential_writes += 1;
                } else {
                    sequential_writes = 0;
                }
                last_addr = pattern.addr;
            }
            if sequential_writes >= SEQUENTIAL_WRITE_THRESHOLD {
                return true;
            }
        }
        false
    }

    pub(super) fn detect_use_after_free_pattern(&self, window: &[AccessPattern]) -> bool {
        if window.len() < 2 {
            return false;
        }
        let first = &window[0];
        let last = &window[window.len() - 1];
        first.addr == last.addr && last.timestamp - first.timestamp > UAF_TIME_THRESHOLD
    }
}
