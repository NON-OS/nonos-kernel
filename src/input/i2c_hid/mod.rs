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

mod api;
mod debug;
pub mod descriptor;
pub mod device;
pub mod init;
pub mod poll;
pub mod protocol;
pub mod state;
pub mod touchpad;

pub use api::*;
pub use debug::{get_touchpad_debug_info, TouchpadDebugInfo};
pub use descriptor::{
    ContactFields, FieldLocation, HidDescriptor, ReportDescriptor, TouchpadLayout,
};
pub use device::{HidDeviceType, I2cHidDevice};
pub use protocol::{HidCommand, HidRegister};
pub use touchpad::{TouchPoint, TouchpadDriver, TouchpadState};
