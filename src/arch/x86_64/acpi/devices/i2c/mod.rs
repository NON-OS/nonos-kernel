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

mod types;
pub mod hids;
mod enumerate;
mod configs;

pub use types::{I2cHidDevice, I2cHidDeviceType};
pub use hids::{classify_hid_device, TOUCHPAD_HIDS, TOUCHSCREEN_HIDS};
pub use enumerate::{enumerate_i2c_hid_devices, find_touchpads, find_touchscreens};
pub use configs::get_additional_touchpad_configs;
