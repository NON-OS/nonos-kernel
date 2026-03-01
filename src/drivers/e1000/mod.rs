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
mod constants;
mod descriptors;
mod device;
pub mod error;
mod interface;

#[cfg(test)]
mod tests;

pub use api::{
    get_e1000_device, get_link_status, get_mac_address, get_stats, handle_interrupt, init_e1000,
    is_present, reclaim_tx,
};
pub use constants::*;
pub use descriptors::{E1000RxDesc, E1000TxDesc};
pub use device::E1000Device;
pub use interface::{register_with_network_stack, E1000SmolBridge, E1000Stats, E1000_SMOL_BRIDGE};
