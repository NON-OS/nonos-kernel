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

extern crate alloc;

pub mod api;
pub mod descriptor;
pub mod device;
pub mod init;
pub mod poll;
pub mod protocol;
pub mod state;
pub mod touchpad;

pub use descriptor::{
    ContactFields, FieldLocation, HidDescriptor, ReportDescriptor, TouchpadLayout,
};
pub use device::{HidDeviceType, I2cHidDevice};
pub use touchpad::{TouchPoint, TouchpadDriver, TouchpadState};
pub use protocol::{HidCommand, HidRegister};

pub use api::{
    get_supported_commands, get_register_address, is_touchpad_usage, is_touchscreen_usage,
    is_mouse_usage, is_keyboard_usage, touchpad_field_usages, hid_usage_pages,
    init_subsystem as init, set_screen_bounds, is_available, touchpad_available,
    touchpad_working, touchpad_position, left_pressed, right_pressed,
    poll_touchpad as poll, device_count, get_device_info, TouchpadDebugInfo,
    get_touchpad_debug_info,
};
