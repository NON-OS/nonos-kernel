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

use super::device_trait::{InputDevice, MAX_INPUT_DEVICES};
use super::error::{InputError, InputErrorCode, InputResult};
use super::push_event;
use super::types::{DeviceId, EventPriority, InputEvent, InputEventKind};
use alloc::vec::Vec;
use spin::Mutex;

pub(super) struct DeviceEntry {
    pub(super) device: &'static dyn InputDevice,
    pub(super) enabled: bool,
}

pub(super) struct DeviceRegistry {
    pub(super) devices: [Option<DeviceEntry>; MAX_INPUT_DEVICES],
    pub(super) count: usize,
}

pub(super) static DEVICE_REGISTRY: Mutex<DeviceRegistry> = Mutex::new({
    const NONE: Option<DeviceEntry> = None;
    DeviceRegistry { devices: [NONE; MAX_INPUT_DEVICES], count: 0 }
});

pub fn unregister_device(device_id: DeviceId) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();
    for slot in registry.devices.iter_mut() {
        if let Some(entry) = slot {
            if entry.device.device_id() == device_id {
                *slot = None;
                registry.count -= 1;
                let event = InputEvent::new(InputEventKind::DeviceDisconnected(device_id))
                    .with_priority(EventPriority::High);
                drop(registry);
                let _ = push_event(event);
                return Ok(());
            }
        }
    }
    Err(InputError::new(InputErrorCode::DeviceNotFound))
}

pub fn poll_all_devices() {
    let registry = DEVICE_REGISTRY.lock();
    for entry in registry.devices.iter().flatten() {
        if !entry.enabled || !entry.device.is_connected() {
            continue;
        }
        while let Some(event) = entry.device.poll() {
            let event = event.with_device(entry.device.device_id());
            if push_event(event).is_err() {
                break;
            }
        }
    }
}

pub fn device_count() -> usize {
    DEVICE_REGISTRY.lock().count
}

pub fn list_devices() -> Vec<(DeviceId, &'static str, bool)> {
    let registry = DEVICE_REGISTRY.lock();
    let mut result = Vec::with_capacity(registry.count);
    for entry in registry.devices.iter().flatten() {
        result.push((
            entry.device.device_id(),
            entry.device.name(),
            entry.enabled && entry.device.is_connected(),
        ));
    }
    result
}

pub fn set_device_enabled(device_id: DeviceId, enabled: bool) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();
    for entry in registry.devices.iter_mut().flatten() {
        if entry.device.device_id() == device_id {
            entry.enabled = enabled;
            return Ok(());
        }
    }
    Err(InputError::new(InputErrorCode::DeviceNotFound))
}
