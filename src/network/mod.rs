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

pub mod api;
pub mod boot_config;
pub mod dhcpv6;
pub mod dns;
pub mod eth;
pub mod ethernet;
pub mod firewall;
pub mod http_client;
pub mod ip;
pub mod ipfs;
pub mod ipv6;
pub mod manager;
pub mod marketplace;
pub mod nft;
pub mod nym;
pub mod onion;
pub mod revenue;
pub mod socket;
pub mod socks;
pub mod stack;
pub mod tcp;
pub mod transparent;
pub mod udp;
pub mod unix;

pub use api::is_network_ready;

pub use manager::{
    configure_ipv4, init, init_with_preset, network_tick, poll_network, run_network_stack,
};
pub use manager::{get_recent_dns_queries, get_suspicious_flows, read_flow_bytes};

pub use stack::get_mac_address_opt as get_mac_address;
pub use stack::{
    get_current_dns, get_current_gateway, get_current_ipv4, get_network_stack, init_network_stack,
    is_network_available, register_device, send_ipv6_packet, ArpEntry, DhcpLease, NetworkStack,
    NetworkStats, SmolDevice, Socket, SocketInfo, TcpSocket,
};

pub use stack::http;

pub use boot_config::{
    deserialize_config as deserialize_network_config, export_as_cmdline as export_network_cmdline,
    get_status as get_network_status, init_from_handoff as init_network_from_handoff,
    parse_cmdline as parse_network_cmdline, preset_anonymous, preset_isolated, preset_maximum,
    preset_standard, print_status as print_network_status,
    serialize_config as serialize_network_config, DnsMode, FirewallConfig, Ipv4Config,
    NetworkBootConfig, OnionConfig, PrivacyMode,
};

pub use nym::{
    get_nym_client, init_nym_client, ClientId, Gateway, GatewayId, MixNode, MixNodeId, NymAddress,
    NymClient, NymError, NymRoute,
};

#[derive(Clone)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Clone)]
pub struct NetworkInterface {
    pub name: alloc::string::String,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub stats: InterfaceStats,
}

pub fn list_interfaces() -> alloc::vec::Vec<NetworkInterface> {
    let mut interfaces = alloc::vec::Vec::new();
    if let Some(stack) = get_network_stack() {
        let stats = stack.stats.lock();
        interfaces.push(NetworkInterface {
            name: alloc::string::String::from("eth0"),
            mac: get_mac_address().unwrap_or([0; 6]),
            mtu: 1500,
            stats: InterfaceStats {
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                rx_packets: stats.rx_packets,
                tx_packets: stats.tx_packets,
            },
        });
    }
    interfaces
}

pub fn get_interface(name: &str) -> Option<NetworkInterface> {
    list_interfaces().into_iter().find(|i| i.name == name)
}

#[cfg(test)]
mod tests;
