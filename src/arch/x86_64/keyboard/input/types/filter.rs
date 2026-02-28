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

use super::device::{DeviceId, EventPriority};
use super::events::{InputEvent, InputEventKind};

#[derive(Debug, Clone, Copy)]
pub struct EventFilter {
    pub keyboard: bool,
    pub mouse: bool,
    pub device: bool,
    pub min_priority: EventPriority,
    pub device_id: Option<DeviceId>,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl EventFilter {
    pub const fn all() -> Self {
        Self {
            keyboard: true,
            mouse: true,
            device: true,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    pub const fn keyboard_only() -> Self {
        Self {
            keyboard: true,
            mouse: false,
            device: false,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    pub const fn mouse_only() -> Self {
        Self {
            keyboard: false,
            mouse: true,
            device: false,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    pub fn matches(&self, event: &InputEvent) -> bool {
        if event.priority < self.min_priority {
            return false;
        }

        if let Some(device_id) = self.device_id {
            if event.device != device_id {
                return false;
            }
        }

        match &event.kind {
            InputEventKind::KeyPress(_) | InputEventKind::KeyRelease(_) => self.keyboard,
            InputEventKind::MouseMove(_)
            | InputEventKind::MouseButton(_)
            | InputEventKind::MouseScroll(_) => self.mouse,
            InputEventKind::DeviceConnected(_) | InputEventKind::DeviceDisconnected(_) => {
                self.device
            }
        }
    }
}
