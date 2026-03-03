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
mod device;
pub mod error;
mod interface;
mod io;

#[cfg(test)]
mod tests;

pub use api::{
    get_link_status, get_mac_address, get_rtl8139_device, get_stats, handle_interrupt,
    init_rtl8139, is_present,
};
pub use constants::*;
pub use device::Rtl8139Device;
pub use interface::{register_with_network_stack, Rtl8139SmolBridge, Rtl8139Stats, RTL8139_SMOL_BRIDGE};
