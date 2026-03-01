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

mod api;
pub mod constants;
pub mod controller;
pub mod dma;
pub mod error;
pub mod stats;
pub mod types;

#[cfg(test)]
mod tests;

pub use api::{get_controller, init_ahci};
pub use controller::{hdr_flags_for, AhciController};
pub use error::AhciError;
pub use stats::AhciStats;
pub use types::{
    AhciDevice, AhciDeviceType, AhciHba, CommandHeader, CommandTable, PhysicalRegionDescriptor,
};
