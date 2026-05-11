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

//! Host fixture for the broker `table` module. Production scans
//! the PCI bus and indexes devices; the host tests inject the
//! exact `DeviceRecord` shape `bind_intx` reads, so the INTx
//! lookup path is exercised end-to-end without needing the PCI
//! enumerator.

use alloc::vec::Vec;
use spin::RwLock;

use super::device::DeviceRecord;

static TABLE: RwLock<Vec<DeviceRecord>> = RwLock::new(Vec::new());

pub fn list() -> Vec<DeviceRecord> {
    TABLE.read().clone()
}

pub fn install_for_test(records: Vec<DeviceRecord>) {
    *TABLE.write() = records;
}

pub fn reset_for_test() {
    TABLE.write().clear();
}
