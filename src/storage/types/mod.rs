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

mod device_info;
mod enums;
mod flags;
mod io_request;
mod io_result;
mod smart_data;

pub use device_info::DeviceInfo;
pub use enums::{IoError, IoOperation, IoStatus, PowerState, StorageType};
pub use flags::{DeviceCapabilities, IoFlags};
pub use io_request::IoRequest;
pub use io_result::{IoCompletionCallback, IoResult};
pub use smart_data::SmartData;
