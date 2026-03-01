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

use crate::capabilities::token::CapabilityToken;
use crate::capabilities::types::Capability;

use super::buffer::BUFFER;
use super::entry::AuditEntry;
use super::stats::STATS;

pub fn log_use(
    token: &CapabilityToken,
    action: &'static str,
    capability: Option<Capability>,
    success: bool,
) {
    let entry = AuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        owner_module: token.owner_module,
        action,
        capability,
        nonce: token.nonce,
        success,
    };

    STATS.record(success);
    BUFFER.lock().push(entry);
}

pub fn log_raw(
    owner_module: u64,
    action: &'static str,
    capability: Option<Capability>,
    nonce: u64,
    success: bool,
) {
    let entry = AuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        owner_module,
        action,
        capability,
        nonce,
        success,
    };

    STATS.record(success);
    BUFFER.lock().push(entry);
}

pub fn log_success(token: &CapabilityToken, action: &'static str, capability: Option<Capability>) {
    log_use(token, action, capability, true);
}

pub fn log_failure(token: &CapabilityToken, action: &'static str, capability: Option<Capability>) {
    log_use(token, action, capability, false);
}

pub fn clear_log() {
    BUFFER.lock().clear();
}

pub fn log_count() -> usize {
    BUFFER.lock().len()
}

pub fn is_empty() -> bool {
    BUFFER.lock().is_empty()
}
