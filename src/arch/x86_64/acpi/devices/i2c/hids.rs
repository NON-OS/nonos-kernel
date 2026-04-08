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

use super::types::I2cHidDeviceType;

pub const TOUCHPAD_HIDS: &[[u8; 8]] = &[
    *b"SYNA3602", *b"SYNA3609", *b"SYNA3619", *b"SYNA7813", *b"SYNA7817",
    *b"ELAN0001", *b"ELAN0100", *b"ELAN0600", *b"ELAN0601", *b"ELAN0602",
    *b"ELAN0603", *b"ELAN0617", *b"ELAN0618", *b"ELAN0619", *b"ELAN0620",
    *b"ELAN0621", *b"ELAN060B", *b"ELAN060C", *b"ELAN0611", *b"ELAN0612",
    *b"ELAN0650", *b"PNP0C50\0", *b"ACPI0C50", *b"MSFT0001",
    *b"ALPS0000", *b"ALPS0001", *b"CYAP0000", *b"CYAP0001", *b"FTSC1000",
];

pub const TOUCHSCREEN_HIDS: &[[u8; 8]] = &[
    *b"ELAN2514", *b"ELAN2097", *b"WCOM0000", *b"WCOM0001", *b"WCOM508C",
    *b"GXTP7380", *b"GXTP7386", *b"ATML1000", *b"ATML1001", *b"FTS3528\0",
];

pub fn classify_hid_device(hid: &[u8; 8]) -> I2cHidDeviceType {
    if TOUCHPAD_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchpad;
    }
    if TOUCHSCREEN_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchscreen;
    }

    let prefix = &hid[0..4];
    match prefix {
        b"SYNA" | b"ELAN" | b"ALPS" | b"CYAP" | b"FTSC" => I2cHidDeviceType::Touchpad,
        b"WCOM" | b"ATML" | b"GXTP" => I2cHidDeviceType::Touchscreen,
        _ => I2cHidDeviceType::Unknown,
    }
}
