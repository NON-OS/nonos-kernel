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
pub enum HidDeviceType {
    Unknown,
    BootKeyboard,
    ReportKeyboard,
    BootMouse,
    ScrollMouse,
    ExtendedMouse,
    Composite,
}

impl HidDeviceType {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown HID Device",
            Self::BootKeyboard => "USB Boot Keyboard",
            Self::ReportKeyboard => "USB Keyboard",
            Self::BootMouse => "USB Boot Mouse",
            Self::ScrollMouse => "USB Scroll Mouse",
            Self::ExtendedMouse => "USB Extended Mouse",
            Self::Composite => "USB Composite Device",
        }
    }
    pub const fn is_keyboard(self) -> bool {
        matches!(self, Self::BootKeyboard | Self::ReportKeyboard)
    }
    pub const fn is_mouse(self) -> bool {
        matches!(self, Self::BootMouse | Self::ScrollMouse | Self::ExtendedMouse)
    }
    pub const fn has_scroll(self) -> bool {
        matches!(self, Self::ScrollMouse | Self::ExtendedMouse)
    }
}
