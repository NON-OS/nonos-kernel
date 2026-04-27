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
mod constants_dma;
mod constants_io;
mod constants_legacy;
mod constants_names;
mod constants_vga;
pub mod error;
pub mod manager;
mod manager_api;
mod manager_core;
pub mod ops;
mod ops_basic;
mod ops_paused;
mod ops_string;
pub mod stats;
mod stats_api;
mod stats_snapshot;
mod stats_types;
pub mod types;

pub use api::{get_stats, port, port_read_only, port_write_only};
pub use constants::*;
pub use error::PortError;
pub use manager::{
    init, is_initialized, is_reserved, release_range, reserve_range, PortManager, PORT_MANAGER,
};
pub use ops::{
    inb, inb_p, inl, insb, insl, insw, inw, inw_p, io_delay, io_delay_n, outb, outb_p, outl, outsb,
    outsl, outsw, outw, outw_p,
};
pub use stats::{PortStats, PortStatsSnapshot, PORT_STATS};
pub use types::{Port, PortRange, PortReadOnly, PortValue, PortWriteOnly};
