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

use super::device::PciDevice;
use super::scan_state::DEVICE_CACHE;
use alloc::vec::Vec;

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    DEVICE_CACHE
        .read()
        .iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
        .copied()
}

pub fn find_devices_by_class(class_code: u8) -> Vec<PciDevice> {
    DEVICE_CACHE.read().iter().filter(|d| d.class_code == class_code).copied().collect()
}

pub fn find_devices_by_class_subclass(class_code: u8, subclass: u8) -> Vec<PciDevice> {
    DEVICE_CACHE
        .read()
        .iter()
        .filter(|d| d.class_code == class_code && d.subclass == subclass)
        .copied()
        .collect()
}
