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

use core::sync::atomic::Ordering;

use super::approval::{ALLOWED_BUS_MASTERS, DEVICE_ALLOWLIST, DEVICE_BLOCKLIST};
use super::validation::{BLOCKED_WRITES, SECURITY_VIOLATIONS};

pub struct SecurityStats {
    pub violations: u64,
    pub blocked_writes: u64,
    pub allowed_bus_masters: u64,
    pub blocklist_size: usize,
    pub allowlist_size: Option<usize>,
}

pub fn get_security_stats() -> SecurityStats {
    let blocklist_size = DEVICE_BLOCKLIST.lock().len();
    let allowlist_size = DEVICE_ALLOWLIST.lock().as_ref().map(|l| l.len());

    SecurityStats {
        violations: SECURITY_VIOLATIONS.load(Ordering::Relaxed),
        blocked_writes: BLOCKED_WRITES.load(Ordering::Relaxed),
        allowed_bus_masters: ALLOWED_BUS_MASTERS.load(Ordering::Relaxed),
        blocklist_size,
        allowlist_size,
    }
}

pub fn reset_security_stats() {
    SECURITY_VIOLATIONS.store(0, Ordering::Relaxed);
    BLOCKED_WRITES.store(0, Ordering::Relaxed);
}
