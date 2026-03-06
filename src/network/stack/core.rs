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


use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
use spin::{Mutex, Once};

use smoltcp::{
    iface::{Interface, SocketSet, Routes, Config as IfaceConfig},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{EthernetAddress, HardwareAddress, IpAddress as SmolIpAddress, IpCidr, Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address},
};

use super::device::{SmolDeviceAdapter, DEFAULT_MAC, now_ms};
use super::types::{ConnectionEntry, NetworkStats, SocketInfo, ArpEntry, Ipv4Address, Ipv6Address};

static STACK: Once<NetworkStack> = Once::new();
static ARP_CACHE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new());

const MAX_ARP_ENTRIES: usize = 64;

pub struct NetworkStack {
    pub(crate) iface: Mutex<Interface>,
    pub(crate) sockets: Mutex<SocketSet<'static>>,
    pub(crate) routes: Mutex<Routes>,
    pub(super) conns: Mutex<BTreeMap<u32, ConnectionEntry>>,
    pub(crate) next_id: AtomicU32,
    pub(crate) stats: Mutex<NetworkStats>,
    pub(crate) default_dns_v4: Mutex<Ipv4Address>,
    pub(crate) gateway_v4: Mutex<Option<[u8; 4]>>,
    pub(crate) gateway_v6: Mutex<Option<[u8; 16]>>,
    pub(crate) default_dns_v6: Mutex<Ipv6Address>,
}

const DEFAULT_DNS_V6: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
];

pub fn init_network_stack() {
    STACK.call_once(|| {
        let mut dev = SmolDeviceAdapter;
        let mut cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(DEFAULT_MAC)));
        cfg.random_seed = 0xD1E5_7A2C;
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(now_ms() as i64));

        let _ = iface.update_ip_addrs(|ips| {
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(127, 0, 0, 1)), 8));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
        });

        NetworkStack {
            iface: Mutex::new(iface),
            sockets: Mutex::new(SocketSet::new(vec![])),
            routes: Mutex::new(Routes::new()),
            conns: Mutex::new(BTreeMap::new()),
            next_id: AtomicU32::new(1),
            stats: Mutex::new(NetworkStats::default()),
            default_dns_v4: Mutex::new([1, 1, 1, 1]),
            gateway_v4: Mutex::new(None),
            gateway_v6: Mutex::new(None),
            default_dns_v6: Mutex::new(DEFAULT_DNS_V6),
        }
    });
}

pub fn get_network_stack() -> Option<&'static NetworkStack> {
    STACK.get()
}

impl NetworkStack {
    pub fn set_ipv4_config(&self, ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>) {
        let mut iface = self.iface.lock();
        let _ = iface.update_ip_addrs(|ips| {
            ips.clear();
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::from_bytes(&ip)), prefix));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
        });
        *self.gateway_v4.lock() = gateway;
        if let Some(gw) = gateway {
            iface.routes_mut().add_default_ipv4_route(SmolIpv4Address::from_bytes(&gw)).ok();
            let mut routes = self.routes.lock();
            routes.add_default_ipv4_route(SmolIpv4Address::from_bytes(&gw)).ok();
        }
    }

    #[inline]
    pub fn poll_interface(&self) {
        let ts = SmolInstant::from_millis(now_ms() as i64);
        let mut iface = self.iface.lock();
        let mut sockets = self.sockets.lock();
        let _ = iface.poll(ts, &mut SmolDeviceAdapter, &mut *sockets);
    }

    #[inline]
    pub(crate) fn poll(&self) { self.poll_interface(); }

    pub(crate) fn pick_single_active_conn(&self) -> Option<u32> {
        let conns = self.conns.lock();
        let mut last: Option<u32> = None;
        for (id, c) in conns.iter() {
            if !c.closed { last = Some(*id); }
        }
        if conns.iter().filter(|(_, c)| !c.closed).count() == 1 { last } else { None }
    }

    pub fn set_default_dns_v4(&self, v4: [u8; 4]) { *self.default_dns_v4.lock() = v4; }

    pub fn get_default_dns_v4(&self) -> [u8; 4] { *self.default_dns_v4.lock() }

    pub fn has_route_to(&self, ip: [u8; 4]) -> bool {
        if ip == [127, 0, 0, 1] {
            return true;
        }
        let gateway = self.gateway_v4.lock();
        if gateway.is_some() {
            return true;
        }
        let iface = self.iface.lock();
        for cidr in iface.ip_addrs() {
            if let SmolIpAddress::Ipv4(v4) = cidr.address() {
                let mask = u32::MAX << (32 - cidr.prefix_len());
                let net = u32::from_be_bytes(v4.0) & mask;
                let target = u32::from_be_bytes(ip) & mask;
                if net == target {
                    return true;
                }
            }
        }
        false
    }

    pub fn get_ipv4_config(&self) -> Option<([u8; 4], u8)> {
        let iface = self.iface.lock();
        for cidr in iface.ip_addrs() {
            if let SmolIpAddress::Ipv4(v4) = cidr.address() {
                if v4.0 != [127, 0, 0, 1] {
                    return Some((v4.0, cidr.prefix_len()));
                }
            }
        }
        None
    }

    pub fn get_gateway_v4(&self) -> Option<[u8; 4]> {
        *self.gateway_v4.lock()
    }

    pub fn get_mac_address(&self) -> [u8; 6] {
        let iface = self.iface.lock();
        let HardwareAddress::Ethernet(eth) = iface.hardware_addr();
        eth.0
    }

    pub fn get_arp_cache(&self) -> Vec<ArpEntry> {
        ARP_CACHE.lock().clone()
    }

    pub fn update_arp_entry(ip: [u8; 4], mac: [u8; 6]) {
        let mut cache = ARP_CACHE.lock();
        if let Some(entry) = cache.iter_mut().find(|e| e.ip == ip) {
            entry.mac = mac;
        } else {
            if cache.len() >= MAX_ARP_ENTRIES {
                cache.remove(0);
            }
            cache.push(ArpEntry { ip, mac });
        }
    }

    pub fn get_socket_info(&self) -> Vec<SocketInfo> {
        let sockets = self.sockets.lock();
        let conns = self.conns.lock();
        let mut result = Vec::new();

        for (_, conn) in conns.iter() {
            let sock: &tcp::Socket = sockets.get(conn.tcp);
            let local_port = sock.local_endpoint().map(|e| e.port).unwrap_or(0);
            let (remote_ip, remote_port) = sock.remote_endpoint().map(|e| {
                let ip = match e.addr {
                    SmolIpAddress::Ipv4(v4) => v4.0,
                    _ => [0, 0, 0, 0],
                };
                (ip, e.port)
            }).unwrap_or(([0, 0, 0, 0], 0));

            let state = if !sock.is_active() { 0 }
                else if sock.is_listening() { 1 }
                else if sock.may_send() && sock.may_recv() { 4 }
                else if !sock.may_recv() { 5 }
                else { 4 };

            let can_recv = sock.may_recv();
            let can_send = sock.may_send();
            let is_closed = conn.closed || !sock.is_active();
            let peer_closed = !sock.may_recv() && sock.is_active();

            result.push(SocketInfo {
                id: conn.id,
                is_tcp: true,
                local_port,
                remote_ip,
                remote_port,
                state,
                rx_available: sock.recv_queue(),
                tx_available: sock.send_queue(),
                can_recv,
                can_send,
                has_error: false,
                is_closed,
                peer_closed,
            });
        }
        result
    }


    pub fn set_ipv6_config(&self, ip: [u8; 16], prefix: u8, gateway: Option<[u8; 16]>) {
        let mut iface = self.iface.lock();

        let ipv4_cidr = iface.ip_addrs().iter()
            .find(|cidr| matches!(cidr.address(), SmolIpAddress::Ipv4(_)))
            .cloned();

        let _ = iface.update_ip_addrs(|ips| {
            ips.clear();
            if let Some(cidr) = ipv4_cidr {
                let _ = ips.push(cidr);
            } else {
                let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(127, 0, 0, 1)), 8));
            }
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&ip)), prefix));
            if ip != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
            }
        });

        *self.gateway_v6.lock() = gateway;
        if let Some(gw) = gateway {
            iface.routes_mut().add_default_ipv6_route(SmolIpv6Address::from_bytes(&gw)).ok();
            let mut routes = self.routes.lock();
            routes.add_default_ipv6_route(SmolIpv6Address::from_bytes(&gw)).ok();
        }
    }

    pub fn set_dual_stack_config(
        &self,
        ipv4: [u8; 4], ipv4_prefix: u8, ipv4_gateway: Option<[u8; 4]>,
        ipv6: [u8; 16], ipv6_prefix: u8, ipv6_gateway: Option<[u8; 16]>,
    ) {
        let mut iface = self.iface.lock();
        let _ = iface.update_ip_addrs(|ips| {
            ips.clear();
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::from_bytes(&ipv4)), ipv4_prefix));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&ipv6)), ipv6_prefix));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
        });

        *self.gateway_v4.lock() = ipv4_gateway;
        *self.gateway_v6.lock() = ipv6_gateway;

        if let Some(gw) = ipv4_gateway {
            iface.routes_mut().add_default_ipv4_route(SmolIpv4Address::from_bytes(&gw)).ok();
        }
        if let Some(gw) = ipv6_gateway {
            iface.routes_mut().add_default_ipv6_route(SmolIpv6Address::from_bytes(&gw)).ok();
        }
    }

    pub fn get_ipv6_config(&self) -> Option<([u8; 16], u8)> {
        let iface = self.iface.lock();
        for cidr in iface.ip_addrs() {
            if let SmolIpAddress::Ipv6(v6) = cidr.address() {
                if v6.0 != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                    return Some((v6.0, cidr.prefix_len()));
                }
            }
        }
        None
    }

    pub fn get_gateway_v6(&self) -> Option<[u8; 16]> {
        *self.gateway_v6.lock()
    }

    pub fn set_default_dns_v6(&self, v6: [u8; 16]) {
        *self.default_dns_v6.lock() = v6;
    }

    pub fn get_default_dns_v6(&self) -> [u8; 16] {
        *self.default_dns_v6.lock()
    }

    pub fn generate_link_local_v6(&self) -> [u8; 16] {
        let mac = self.get_mac_address();
        let mut addr = [0u8; 16];

        addr[0] = 0xfe;
        addr[1] = 0x80;

        addr[8] = mac[0] ^ 0x02;
        addr[9] = mac[1];
        addr[10] = mac[2];
        addr[11] = 0xff;
        addr[12] = 0xfe;
        addr[13] = mac[3];
        addr[14] = mac[4];
        addr[15] = mac[5];

        addr
    }

    pub fn configure_link_local_v6(&self) {
        let link_local = self.generate_link_local_v6();
        let mut iface = self.iface.lock();

        let _ = iface.update_ip_addrs(|ips| {
            let has_link_local = ips.iter().any(|cidr| {
                if let SmolIpAddress::Ipv6(v6) = cidr.address() {
                    v6.0[0] == 0xfe && (v6.0[1] & 0xc0) == 0x80
                } else {
                    false
                }
            });
            if !has_link_local {
                let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&link_local)), 64));
            }
        });
    }

    pub fn has_ipv6(&self) -> bool {
        self.get_ipv6_config().is_some()
    }

    pub fn has_dual_stack(&self) -> bool {
        self.get_ipv4_config().is_some() && self.get_ipv6_config().is_some()
    }
}
