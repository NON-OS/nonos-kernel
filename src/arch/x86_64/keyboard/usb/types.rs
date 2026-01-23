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

pub const HID_CLASS: u8 = 0x03;
pub const HID_SUBCLASS_BOOT: u8 = 0x01;
pub const HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const HID_PROTOCOL_MOUSE: u8 = 0x02;
pub const MAX_HID_DEVICES: usize = 8;
pub const MAX_KEYS_PRESSED: usize = 6;
pub const KEYBOARD_REPORT_SIZE: usize = 8;
pub const MOUSE_REPORT_MIN_SIZE: usize = 3;
pub const MOUSE_REPORT_SCROLL_SIZE: usize = 4;

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

#[derive(Debug, Clone, Copy, Default)]
pub struct ModifierState {
    pub left_ctrl: bool,
    pub left_shift: bool,
    pub left_alt: bool,
    pub left_gui: bool,
    pub right_ctrl: bool,
    pub right_shift: bool,
    pub right_alt: bool,
    pub right_gui: bool,
}

impl ModifierState {
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            left_ctrl: (byte & 0x01) != 0,
            left_shift: (byte & 0x02) != 0,
            left_alt: (byte & 0x04) != 0,
            left_gui: (byte & 0x08) != 0,
            right_ctrl: (byte & 0x10) != 0,
            right_shift: (byte & 0x20) != 0,
            right_alt: (byte & 0x40) != 0,
            right_gui: (byte & 0x80) != 0,
        }
    }

    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.left_ctrl { byte |= 0x01; }
        if self.left_shift { byte |= 0x02; }
        if self.left_alt { byte |= 0x04; }
        if self.left_gui { byte |= 0x08; }
        if self.right_ctrl { byte |= 0x10; }
        if self.right_shift { byte |= 0x20; }
        if self.right_alt { byte |= 0x40; }
        if self.right_gui { byte |= 0x80; }
        byte
    }

    pub const fn shift(self) -> bool {
        self.left_shift || self.right_shift
    }

    pub const fn ctrl(self) -> bool {
        self.left_ctrl || self.right_ctrl
    }

    pub const fn alt(self) -> bool {
        self.left_alt || self.right_alt
    }

    pub const fn gui(self) -> bool {
        self.left_gui || self.right_gui
    }

    pub const fn altgr(self) -> bool {
        self.right_alt
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LedState {
    pub num_lock: bool,
    pub caps_lock: bool,
    pub scroll_lock: bool,
    pub compose: bool,
    pub kana: bool,
}

impl LedState {
    pub const fn new() -> Self {
        Self {
            num_lock: false,
            caps_lock: false,
            scroll_lock: false,
            compose: false,
            kana: false,
        }
    }

    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.num_lock { byte |= 0x01; }
        if self.caps_lock { byte |= 0x02; }
        if self.scroll_lock { byte |= 0x04; }
        if self.compose { byte |= 0x08; }
        if self.kana { byte |= 0x10; }
        byte
    }

    pub const fn from_byte(byte: u8) -> Self {
        Self {
            num_lock: (byte & 0x01) != 0,
            caps_lock: (byte & 0x02) != 0,
            scroll_lock: (byte & 0x04) != 0,
            compose: (byte & 0x08) != 0,
            kana: (byte & 0x10) != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MouseButtonState {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub button4: bool,
    pub button5: bool,
}

impl MouseButtonState {
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            left: (byte & 0x01) != 0,
            right: (byte & 0x02) != 0,
            middle: (byte & 0x04) != 0,
            button4: (byte & 0x08) != 0,
            button5: (byte & 0x10) != 0,
        }
    }

    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.left { byte |= 0x01; }
        if self.right { byte |= 0x02; }
        if self.middle { byte |= 0x04; }
        if self.button4 { byte |= 0x08; }
        if self.button5 { byte |= 0x10; }
        byte
    }

    pub const fn get(self, index: u8) -> bool {
        match index {
            0 => self.left,
            1 => self.right,
            2 => self.middle,
            3 => self.button4,
            4 => self.button5,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UsbHidStats {
    pub keyboard_reports: u32,
    pub mouse_reports: u32,
    pub key_presses: u32,
    pub key_releases: u32,
    pub mouse_moves: u32,
    pub mouse_buttons: u32,
    pub poll_cycles: u32,
    pub errors: u32,
    pub devices_connected: u8,
    pub devices_disconnected: u8,
}

impl UsbHidStats {
    pub const fn new() -> Self {
        Self {
            keyboard_reports: 0,
            mouse_reports: 0,
            key_presses: 0,
            key_releases: 0,
            mouse_moves: 0,
            mouse_buttons: 0,
            poll_cycles: 0,
            errors: 0,
            devices_connected: 0,
            devices_disconnected: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HidDeviceInfo {
    pub slot_id: u8,
    pub device_type: HidDeviceType,
    pub report_count: u32,
    pub error_count: u32,
}
