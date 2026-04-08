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

pub use super::constants_general::{
    MAX_BARS, MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE, MAX_PCI_BUSES,
    PCI_CONFIG_ADDRESS, PCI_CONFIG_DATA,
};
pub use super::constants_config as config;
pub use super::constants_command as command;
pub use super::constants_status as status;
pub use super::constants_capability as capability;
pub use super::constants_class as class_codes;
pub use super::constants_names::get_class_name;
