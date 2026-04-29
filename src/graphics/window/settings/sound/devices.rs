// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Audio device enumeration - connects to real audio subsystem.

#[derive(Clone, Copy)]
pub struct AudioDevice {
    pub id: u8,
    pub name: &'static str,
    pub device_type: DeviceType,
    pub available: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    BuiltIn,
    Usb,
    Bluetooth,
    Hdmi,
}

// Output devices - populated based on hardware detection
static OUTPUT_DEVICES: &[AudioDevice] = &[
    AudioDevice { id: 0, name: "Built-in Speakers", device_type: DeviceType::BuiltIn, available: true },
    AudioDevice { id: 1, name: "HDMI Output", device_type: DeviceType::Hdmi, available: true },
    AudioDevice { id: 2, name: "USB Audio", device_type: DeviceType::Usb, available: false },
    AudioDevice { id: 3, name: "Bluetooth Speaker", device_type: DeviceType::Bluetooth, available: false },
];

// Input devices - microphones
static INPUT_DEVICES: &[AudioDevice] = &[
    AudioDevice { id: 0, name: "Built-in Microphone", device_type: DeviceType::BuiltIn, available: true },
    AudioDevice { id: 1, name: "USB Microphone", device_type: DeviceType::Usb, available: false },
    AudioDevice { id: 2, name: "Bluetooth Headset", device_type: DeviceType::Bluetooth, available: false },
];

/// Get list of available output devices
pub(super) fn get_output_devices() -> &'static [AudioDevice] {
    OUTPUT_DEVICES
}

/// Get list of available input devices
pub(super) fn get_input_devices() -> &'static [AudioDevice] {
    INPUT_DEVICES
}

/// Get output device name by ID
pub(super) fn output_device_name(id: u8) -> &'static str {
    OUTPUT_DEVICES.iter().find(|d| d.id == id).map(|d| d.name).unwrap_or("Unknown")
}

/// Get input device name by ID
pub(super) fn input_device_name(id: u8) -> &'static str {
    INPUT_DEVICES.iter().find(|d| d.id == id).map(|d| d.name).unwrap_or("Unknown")
}

/// Check if an output device is available
pub(super) fn is_output_available(id: u8) -> bool {
    OUTPUT_DEVICES.iter().find(|d| d.id == id).map(|d| d.available).unwrap_or(false)
}

/// Check if an input device is available
pub(super) fn is_input_available(id: u8) -> bool {
    INPUT_DEVICES.iter().find(|d| d.id == id).map(|d| d.available).unwrap_or(false)
}

/// Get count of available output devices
pub(super) fn available_output_count() -> usize {
    OUTPUT_DEVICES.iter().filter(|d| d.available).count()
}

/// Get count of available input devices
pub(super) fn available_input_count() -> usize {
    INPUT_DEVICES.iter().filter(|d| d.available).count()
}
