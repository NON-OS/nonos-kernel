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

mod bars;
pub mod bars_io;
pub mod bars_mem;
mod capabilities;
mod capabilities_errors;
mod capabilities_find;
mod capabilities_msix;
mod commands;
mod device;
mod device_accessors;
mod device_new;
mod device_struct;

pub use bars_io::parse_io_bar;
pub use bars_mem::parse_mem_bar;
pub use device::PciDevice;
