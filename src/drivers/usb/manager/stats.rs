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

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct UsbStats {
    pub devices_enumerated: AtomicU64,
    pub ctrl_transfers: AtomicU64,
    pub ctrl_errors: AtomicU64,
    pub bulk_transfers: AtomicU64,
    pub bulk_errors: AtomicU64,
    pub int_transfers: AtomicU64,
    pub int_errors: AtomicU64,
}

impl UsbStats {
    pub fn snapshot(&self) -> UsbStatsSnapshot {
        UsbStatsSnapshot {
            devices_enumerated: self.devices_enumerated.load(Ordering::Relaxed),
            ctrl_transfers: self.ctrl_transfers.load(Ordering::Relaxed),
            ctrl_errors: self.ctrl_errors.load(Ordering::Relaxed),
            bulk_transfers: self.bulk_transfers.load(Ordering::Relaxed),
            bulk_errors: self.bulk_errors.load(Ordering::Relaxed),
            int_transfers: self.int_transfers.load(Ordering::Relaxed),
            int_errors: self.int_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UsbStatsSnapshot {
    pub devices_enumerated: u64,
    pub ctrl_transfers: u64,
    pub ctrl_errors: u64,
    pub bulk_transfers: u64,
    pub bulk_errors: u64,
    pub int_transfers: u64,
    pub int_errors: u64,
}
