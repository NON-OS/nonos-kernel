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

/*
 * TCP/IP network stack for NONOS.
 *
 * Built on smoltcp with custom device adapter for WiFi/Ethernet drivers.
 * Supports IPv4/IPv6 dual-stack, TCP sockets, DNS resolution, DHCP,
 * and HTTP/HTTPS clients. See core.rs for the main NetworkStack singleton.
 */

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
pub mod types;
pub mod util;

pub use api::{is_network_connected, set_network_connected, get_socket_info, get_current_ipv4, get_current_gateway, get_current_dns, get_mac_address, is_network_available};
pub use device::{register_device, SmolDevice, SmolDeviceAdapter};
pub use core::{get_network_stack, init_network_stack, NetworkStack};
pub use types::{
    ArpEntry, DhcpLease, Ipv4Address, Ipv6Address, NetworkStats, SmolHandle, Socket, SocketInfo,
    TcpSocket,
};
