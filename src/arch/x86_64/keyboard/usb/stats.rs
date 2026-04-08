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

use super::device_type::HidDeviceType;

#[derive(Debug, Clone, Copy)]
pub struct UsbHidStats {
    pub keyboard_reports: u32, pub mouse_reports: u32, pub key_presses: u32, pub key_releases: u32,
    pub mouse_moves: u32, pub mouse_buttons: u32, pub poll_cycles: u32, pub errors: u32,
    pub devices_connected: u8, pub devices_disconnected: u8,
}

impl UsbHidStats {
    pub const fn new() -> Self {
        Self { keyboard_reports: 0, mouse_reports: 0, key_presses: 0, key_releases: 0, mouse_moves: 0,
               mouse_buttons: 0, poll_cycles: 0, errors: 0, devices_connected: 0, devices_disconnected: 0 }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HidDeviceInfo {
    pub slot_id: u8,
    pub device_type: HidDeviceType,
    pub report_count: u32,
    pub error_count: u32,
}
