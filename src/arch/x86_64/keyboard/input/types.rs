// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::get_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u16);

impl DeviceId {
    pub const KEYBOARD: Self = Self(0);
    pub const MOUSE: Self = Self(1);
    pub const VIRTUAL: Self = Self(0xFFFF);
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::KEYBOARD
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EventPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for EventPriority {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    bits: u16,
}

impl Modifiers {
    pub const NONE: Self = Self { bits: 0 };
    pub const SHIFT: Self = Self { bits: 1 << 0 };
    pub const CTRL: Self = Self { bits: 1 << 1 };
    pub const ALT: Self = Self { bits: 1 << 2 };
    pub const META: Self = Self { bits: 1 << 3 };
    pub const CAPS_LOCK: Self = Self { bits: 1 << 4 };
    pub const NUM_LOCK: Self = Self { bits: 1 << 5 };
    pub const SCROLL_LOCK: Self = Self { bits: 1 << 6 };

    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    pub const fn bits(self) -> u16 {
        self.bits
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub scan_code: u8,
    pub pressed: bool,
    pub modifiers: Modifiers,
    pub repeat_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    Side1 = 3,
    Side2 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseMoveEvent {
    pub dx: i16,
    pub dy: i16,
    pub abs_x: Option<u16>,
    pub abs_y: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseButtonEvent {
    pub button: MouseButton,
    pub pressed: bool,
    pub click_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseScrollEvent {
    pub delta_y: i8,
    pub delta_x: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
