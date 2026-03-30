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

mod enums;
mod flags;
mod io_result;
mod io_request;
mod device_info;
mod smart_data;

pub use enums::{StorageType, PowerState, IoOperation, IoStatus, IoError};
pub use flags::{IoFlags, DeviceCapabilities};
pub use io_result::{IoResult, IoCompletionCallback};
pub use io_request::IoRequest;
pub use device_info::DeviceInfo;
pub use smart_data::SmartData;
