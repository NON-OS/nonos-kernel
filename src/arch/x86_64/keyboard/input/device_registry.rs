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

use super::device_trait::InputDevice;
use super::error::{InputError, InputErrorCode, InputResult};
use super::types::{EventPriority, InputEvent, InputEventKind};
use super::push_event;
use super::device_ops::DEVICE_REGISTRY;

pub fn register_device(device: &'static dyn InputDevice) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();
    let device_id = device.device_id();
    for entry in registry.devices.iter().flatten() {
        if entry.device.device_id() == device_id {
            return Err(InputError::with_context(InputErrorCode::InvalidConfig, "device already registered"));
        }
    }
    for slot in registry.devices.iter_mut() {
        if slot.is_none() {
            *slot = Some(super::device_ops::DeviceEntry { device, enabled: true });
            registry.count += 1;
            let event = InputEvent::new(InputEventKind::DeviceConnected(device_id)).with_priority(EventPriority::High);
            drop(registry);
            let _ = push_event(event);
            return Ok(());
        }
    }
    Err(InputError::with_context(InputErrorCode::ResourceExhausted, "device registry full"))
}
