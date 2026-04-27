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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) struct Device {
    pub id: u32,
    pub name: [u8; 32],
    pub class: u8,
    pub subclass: u8,
    pub vendor_id: u16,
    pub product_id: u16,
}

static DEVICES: Mutex<[Option<Device>; 32]> = Mutex::new([const { None }; 32]);
static NEXT_DEV_ID: AtomicU32 = AtomicU32::new(1);

pub(super) fn register_device(name: &[u8], class: u8, subclass: u8, vid: u16, pid: u16) -> u32 {
    let id = NEXT_DEV_ID.fetch_add(1, Ordering::Relaxed);
    let mut dev_name = [0u8; 32];
    let len = core::cmp::min(name.len(), 32);
    dev_name[..len].copy_from_slice(&name[..len]);
    let mut devices = DEVICES.lock();
    for slot in devices.iter_mut() {
        if slot.is_none() {
            *slot = Some(Device {
                id,
                name: dev_name,
                class,
                subclass,
                vendor_id: vid,
                product_id: pid,
            });
            return id;
        }
    }
    0
}

pub(super) fn unregister_device(id: u32) -> bool {
    let mut devices = DEVICES.lock();
    for slot in devices.iter_mut() {
        if let Some(dev) = slot {
            if dev.id == id {
                *slot = None;
                return true;
            }
        }
    }
    false
}

pub(super) fn get_device(id: u32) -> Option<Device> {
    let devices = DEVICES.lock();
    for slot in devices.iter() {
        if let Some(dev) = slot {
            if dev.id == id {
                return Some(Device {
                    id: dev.id,
                    name: dev.name,
                    class: dev.class,
                    subclass: dev.subclass,
                    vendor_id: dev.vendor_id,
                    product_id: dev.product_id,
                });
            }
        }
    }
    None
}

pub(super) fn device_count() -> u32 {
    DEVICES.lock().iter().filter(|d| d.is_some()).count() as u32
}
