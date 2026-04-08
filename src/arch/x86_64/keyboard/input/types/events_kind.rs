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

use super::device::DeviceId;
use super::modifiers::KeyEvent;
use super::mouse::{MouseButtonEvent, MouseMoveEvent, MouseScrollEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum InputEventKind {
    KeyPress(KeyEvent),
    KeyRelease(KeyEvent),
    MouseMove(MouseMoveEvent),
    MouseButton(MouseButtonEvent),
    MouseScroll(MouseScrollEvent),
    DeviceConnected(DeviceId),
    DeviceDisconnected(DeviceId),
}

impl InputEventKind {
    pub const fn is_key_event(&self) -> bool { matches!(self, Self::KeyPress(_) | Self::KeyRelease(_)) }
    pub const fn is_mouse_event(&self) -> bool {
        matches!(self, Self::MouseMove(_) | Self::MouseButton(_) | Self::MouseScroll(_))
    }
    pub const fn is_device_event(&self) -> bool {
        matches!(self, Self::DeviceConnected(_) | Self::DeviceDisconnected(_))
    }
    pub const fn scan_code(&self) -> Option<u8> {
        match self {
            Self::KeyPress(k) | Self::KeyRelease(k) => Some(k.scan_code),
            _ => None,
        }
    }
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::KeyPress(_) => "KeyPress", Self::KeyRelease(_) => "KeyRelease",
            Self::MouseMove(_) => "MouseMove", Self::MouseButton(_) => "MouseButton",
            Self::MouseScroll(_) => "MouseScroll", Self::DeviceConnected(_) => "DeviceConnected",
            Self::DeviceDisconnected(_) => "DeviceDisconnected",
        }
    }
}
