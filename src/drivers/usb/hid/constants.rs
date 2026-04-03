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

pub const HID_SUBCLASS_NONE: u8 = 0x00;
pub const HID_SUBCLASS_BOOT: u8 = 0x01;

pub const HID_PROTOCOL_NONE: u8 = 0x00;
pub const HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const HID_PROTOCOL_MOUSE: u8 = 0x02;

pub const HID_DT_HID: u8 = 0x21;
pub const HID_DT_REPORT: u8 = 0x22;
pub const HID_DT_PHYSICAL: u8 = 0x23;

pub const HID_REQ_GET_REPORT: u8 = 0x01;
pub const HID_REQ_GET_IDLE: u8 = 0x02;
pub const HID_REQ_GET_PROTOCOL: u8 = 0x03;
pub const HID_REQ_SET_REPORT: u8 = 0x09;
pub const HID_REQ_SET_IDLE: u8 = 0x0A;
pub const HID_REQ_SET_PROTOCOL: u8 = 0x0B;

pub const HID_REPORT_TYPE_INPUT: u8 = 0x01;
pub const HID_REPORT_TYPE_OUTPUT: u8 = 0x02;
pub const HID_REPORT_TYPE_FEATURE: u8 = 0x03;

pub const HID_BOOT_PROTOCOL: u8 = 0x00;
pub const HID_REPORT_PROTOCOL: u8 = 0x01;

pub const BOOT_KEYBOARD_REPORT_SIZE: usize = 8;
pub const BOOT_MOUSE_REPORT_SIZE: usize = 3;

pub const KEYBOARD_LED_NUM_LOCK: u8 = 0x01;
pub const KEYBOARD_LED_CAPS_LOCK: u8 = 0x02;
pub const KEYBOARD_LED_SCROLL_LOCK: u8 = 0x04;
pub const KEYBOARD_LED_COMPOSE: u8 = 0x08;
pub const KEYBOARD_LED_KANA: u8 = 0x10;

pub const MOD_LEFT_CTRL: u8 = 0x01;
pub const MOD_LEFT_SHIFT: u8 = 0x02;
pub const MOD_LEFT_ALT: u8 = 0x04;
pub const MOD_LEFT_GUI: u8 = 0x08;
pub const MOD_RIGHT_CTRL: u8 = 0x10;
pub const MOD_RIGHT_SHIFT: u8 = 0x20;
pub const MOD_RIGHT_ALT: u8 = 0x40;
pub const MOD_RIGHT_GUI: u8 = 0x80;

pub const MOUSE_BTN_LEFT: u8 = 0x01;
pub const MOUSE_BTN_RIGHT: u8 = 0x02;
pub const MOUSE_BTN_MIDDLE: u8 = 0x04;

pub const MAX_HID_DEVICES: usize = 8;
pub const HID_POLL_INTERVAL_MS: u64 = 10;
