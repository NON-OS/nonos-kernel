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

use super::super::get_timestamp;
use super::device::{DeviceId, EventPriority};
use super::modifiers::{KeyEvent, Modifiers};
use super::mouse::{MouseButton, MouseButtonEvent, MouseMoveEvent, MouseScrollEvent};

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
    pub const fn is_key_event(&self) -> bool {
        matches!(self, Self::KeyPress(_) | Self::KeyRelease(_))
    }

    pub const fn is_mouse_event(&self) -> bool {
        matches!(
            self,
            Self::MouseMove(_) | Self::MouseButton(_) | Self::MouseScroll(_)
        )
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
            Self::KeyPress(_) => "KeyPress",
            Self::KeyRelease(_) => "KeyRelease",
            Self::MouseMove(_) => "MouseMove",
            Self::MouseButton(_) => "MouseButton",
            Self::MouseScroll(_) => "MouseScroll",
            Self::DeviceConnected(_) => "DeviceConnected",
            Self::DeviceDisconnected(_) => "DeviceDisconnected",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InputEvent {
    pub kind: InputEventKind,
    pub timestamp: u64,
    pub device: DeviceId,
    pub priority: EventPriority,
    pub sequence: u64,
}

impl InputEvent {
    pub fn new(kind: InputEventKind) -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        Self {
            kind,
            timestamp: get_timestamp(),
            device: DeviceId::default(),
            priority: EventPriority::default(),
            sequence: SEQUENCE.fetch_add(1, Ordering::SeqCst),
        }
    }

    pub fn with_device(mut self, device: DeviceId) -> Self {
        self.device = device;
        self
    }

    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn key_press(scan_code: u8) -> Self {
        Self::new(InputEventKind::KeyPress(KeyEvent {
            scan_code,
            pressed: true,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        }))
    }

    pub fn key_release(scan_code: u8) -> Self {
        Self::new(InputEventKind::KeyRelease(KeyEvent {
            scan_code,
            pressed: false,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        }))
    }

    pub fn mouse_move(dx: i16, dy: i16) -> Self {
        Self::new(InputEventKind::MouseMove(MouseMoveEvent {
            dx,
            dy,
            abs_x: None,
            abs_y: None,
        }))
        .with_device(DeviceId::MOUSE)
    }

    pub fn mouse_button(button: u8, pressed: bool) -> Self {
        let btn = match button {
            0 => MouseButton::Left,
            1 => MouseButton::Right,
            2 => MouseButton::Middle,
            3 => MouseButton::Side1,
            4 => MouseButton::Side2,
            _ => MouseButton::Left,
        };
        Self::new(InputEventKind::MouseButton(MouseButtonEvent {
            button: btn,
            pressed,
            click_count: 1,
        }))
        .with_device(DeviceId::MOUSE)
    }

    pub fn mouse_scroll(delta: i8) -> Self {
        Self::new(InputEventKind::MouseScroll(MouseScrollEvent {
            delta_y: delta,
            delta_x: 0,
        }))
        .with_device(DeviceId::MOUSE)
    }
}

impl PartialEq for InputEvent {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
    }
}

impl Eq for InputEvent {}
