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

pub mod arp;
pub mod filter;
pub mod headers;
pub mod interface;
pub mod packet;
pub mod udp;

pub use arp::{arp_insert, arp_lookup};
pub use filter::{add_filter, FilterAction, PacketFilter};
pub use headers::{ipv4_from_octets, ipv4_from_u32};
pub use interface::{
    get_default_interface, get_ipv4, get_mac, register_interface, set_default_interface, set_ipv4,
    NetworkInterface, NetworkStats,
};
pub use packet::{receive_packet, try_send_raw};
pub use udp::{udp_listen, udp_send};
