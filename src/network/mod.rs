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
pub mod boot_config;
pub mod dns;
pub mod ethernet;
pub mod firewall;
pub mod http_client;
pub mod ip;
pub mod manager;
pub mod onion;
pub mod socks;
pub mod stack;
pub mod tcp;
pub mod transparent;
pub mod udp;

pub use api::is_network_ready;

pub use manager::{
    configure_ipv4, init, init_with_preset,
    network_tick, poll_network, run_network_stack,
};
pub use manager::{get_recent_dns_queries, get_suspicious_flows, read_flow_bytes};

pub use stack::{
    get_network_stack, init_network_stack, register_device, ArpEntry, DhcpLease, NetworkStack,
    NetworkStats, SmolDevice, Socket, SocketInfo, TcpSocket,
    get_current_ipv4, get_current_gateway, get_current_dns, get_mac_address,
    is_network_available,
};

pub use stack::http;

pub use boot_config::{
    deserialize_config as deserialize_network_config,
    export_as_cmdline as export_network_cmdline,
    get_status as get_network_status,
    init_from_handoff as init_network_from_handoff,
    parse_cmdline as parse_network_cmdline,
    preset_anonymous, preset_isolated, preset_maximum, preset_standard,
    print_status as print_network_status,
    serialize_config as serialize_network_config,
    DnsMode, FirewallConfig, Ipv4Config, NetworkBootConfig, OnionConfig, PrivacyMode,
};
