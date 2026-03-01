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
use spin::Mutex;
use super::types::ThreatDetectionEngine;

pub struct KernelThreatAI {
    detections: AtomicU64,
    last_threat: Mutex<Option<String>>,
}

impl KernelThreatAI {
    pub fn new() -> Self {
        Self {
            detections: AtomicU64::new(0),
            last_threat: Mutex::new(None),
        }
    }
}

impl ThreatDetectionEngine for KernelThreatAI {
    fn detect_threat(&self, input: &[u8]) -> Option<String> {
        if input.len() > 1024 && crate::crypto::estimate_entropy(input) > 7.5 {
            self.detections.fetch_add(1, Ordering::Relaxed);
            let threat: String = "High-entropy anomaly detected".into();
            *self.last_threat.lock() = Some(threat.clone());
            Some(threat)
        } else {
            None
        }
    }

    fn report(&self) -> u64 {
        self.detections.load(Ordering::Relaxed)
    }
}
