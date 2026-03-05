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
pub mod controller;
pub mod error;
pub mod pci;
pub mod types;

pub use api::{controller_count, get_controller, read, write, write_read};
pub(crate) use api::CONTROLLERS;
pub use controller::DesignWareI2c;
pub use error::I2cError;
pub use pci::{detect_hid_devices, find_lpss_controllers, init, LpssController};
pub use types::{I2cAddress, I2cMessage, I2cSpeed, I2cTransaction};
