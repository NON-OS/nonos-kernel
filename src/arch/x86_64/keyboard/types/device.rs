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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Keyboard,
    Mouse,
    Touchpad,
    Gamepad,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u16);

impl DeviceId {
    pub const INVALID: Self = Self(0xFFFF);
    pub const PS2_KEYBOARD: Self = Self(0x0001);
    pub const PS2_MOUSE: Self = Self(0x0002);
    pub const USB_BASE: u16 = 0x1000;

    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0xFFFF
    }

    pub const fn is_ps2(self) -> bool {
        self.0 < Self::USB_BASE
    }

    pub const fn is_usb(self) -> bool {
        self.0 >= Self::USB_BASE && self.0 != 0xFFFF
    }

    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::INVALID
    }
}
