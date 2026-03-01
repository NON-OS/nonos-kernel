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
use alloc::vec::Vec;
use spin::Mutex;
use super::types::QuantumAuditEvent;

pub struct QuantumAuditLog {
    events: Mutex<Vec<QuantumAuditEvent>>,
}

impl QuantumAuditLog {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn log_event(&self, event_type: &str, details: &str, key_id: Option<[u8; 32]>) {
        self.events.lock().push(QuantumAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event_type: event_type.into(),
            details: details.into(),
            key_id,
        })
    }

    pub fn recent(&self, n: usize) -> Vec<QuantumAuditEvent> {
        let log = self.events.lock();
        log.iter().rev().take(n).cloned().collect()
    }
}
