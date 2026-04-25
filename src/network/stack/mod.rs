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

pub mod api;
pub mod async_ops;
pub mod config;
pub mod core;
pub mod device;
pub mod dhcp;
pub mod dns_impl;
pub mod http;
pub mod icmp;
pub mod sockets;
pub mod tcp;
mod tcp_methods;
pub mod types;
pub mod util;

pub use api::{
    get_current_dns, get_current_gateway, get_current_ipv4, get_mac_address, get_mac_address_opt,
    get_socket_info, is_link_up, is_network_available, is_network_connected, send_ipv6_packet,
    set_network_connected,
};
pub use core::{get_network_stack, init_network_stack, NetworkStack};
pub use device::{register_device, SmolDevice, SmolDeviceAdapter};
pub use tcp::{TcpConfig, TcpTimeouts, DEFAULT_TCP_CONFIG};
pub use types::{
    ArpEntry, DhcpLease, Ipv4Address, Ipv6Address, NetworkStats, SmolHandle, Socket, SocketInfo,
    TcpSocket,
};
