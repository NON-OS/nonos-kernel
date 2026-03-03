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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::super::error::{PciError, Result};

pub(super) static ALLOWED_BUS_MASTERS: AtomicU64 = AtomicU64::new(0);
pub(super) static BUS_MASTER_APPROVED: Mutex<Vec<(u8, u8, u8)>> = Mutex::new(Vec::new());
pub(super) static DEVICE_BLOCKLIST: Mutex<Vec<(u16, u16)>> = Mutex::new(Vec::new());
pub(super) static DEVICE_ALLOWLIST: Mutex<Option<Vec<(u16, u16)>>> = Mutex::new(None);

pub fn is_bus_master_approved(bus: u8, device: u8, function: u8) -> bool {
    let approved = BUS_MASTER_APPROVED.lock();
    approved.iter().any(|(b, d, f)| *b == bus && *d == device && *f == function)
}

pub fn approve_bus_master(bus: u8, device: u8, function: u8) {
    let mut approved = BUS_MASTER_APPROVED.lock();
    if !approved.iter().any(|(b, d, f)| *b == bus && *d == device && *f == function) {
        approved.push((bus, device, function));
        ALLOWED_BUS_MASTERS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn revoke_bus_master(bus: u8, device: u8, function: u8) {
    let mut approved = BUS_MASTER_APPROVED.lock();
    approved.retain(|(b, d, f)| !(*b == bus && *d == device && *f == function));
}

pub fn clear_bus_master_approvals() {
    BUS_MASTER_APPROVED.lock().clear();
}

pub fn check_device_allowed(vendor_id: u16, device_id: u16) -> Result<()> {
    let blocklist = DEVICE_BLOCKLIST.lock();
    if blocklist.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        return Err(PciError::DeviceBlocked {
            vendor: vendor_id,
            device: device_id,
        });
    }
    drop(blocklist);

    let allowlist = DEVICE_ALLOWLIST.lock();
    if let Some(ref list) = *allowlist {
        if !list.is_empty() && !list.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
            return Err(PciError::DeviceNotAllowed {
                vendor: vendor_id,
                device: device_id,
            });
        }
    }

    Ok(())
}

pub fn add_to_blocklist(vendor_id: u16, device_id: u16) {
    let mut blocklist = DEVICE_BLOCKLIST.lock();
    if !blocklist.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        blocklist.push((vendor_id, device_id));
    }
}

pub fn remove_from_blocklist(vendor_id: u16, device_id: u16) {
    let mut blocklist = DEVICE_BLOCKLIST.lock();
    blocklist.retain(|(v, d)| !(*v == vendor_id && *d == device_id));
}

pub fn clear_blocklist() {
    DEVICE_BLOCKLIST.lock().clear();
}

pub fn set_allowlist(list: Option<Vec<(u16, u16)>>) {
    *DEVICE_ALLOWLIST.lock() = list;
}

pub fn add_to_allowlist(vendor_id: u16, device_id: u16) {
    let mut allowlist = DEVICE_ALLOWLIST.lock();
    let list = allowlist.get_or_insert_with(Vec::new);
    if !list.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        list.push((vendor_id, device_id));
    }
}

pub fn clear_allowlist() {
    *DEVICE_ALLOWLIST.lock() = None;
}
