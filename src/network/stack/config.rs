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
 * Network stack IP address configuration.
 *
 * Handles IPv4, IPv6, and dual-stack configuration for the network interface.
 * Supports:
 * - Static IPv4/IPv6 address assignment with CIDR prefix
 * - Default gateway configuration for both protocols
 * - DNS server configuration (Cloudflare 1.1.1.1 default for IPv4)
 * - IPv6 link-local address generation from MAC (EUI-64)
 * - Dual-stack operation with simultaneous IPv4 + IPv6
 */

use smoltcp::wire::{
    IpAddress as SmolIpAddress, IpCidr,
    Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address,
};

use super::core::NetworkStack;
use super::types::{Ipv4Address, Ipv6Address};

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

    pub fn set_default_dns_v4(&self, v4: Ipv4Address) {
        *self.default_dns_v4.lock() = v4;
    }

    pub fn get_default_dns_v4(&self) -> Ipv4Address {
        *self.default_dns_v4.lock()
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

    pub fn set_default_dns_v6(&self, v6: Ipv6Address) {
        *self.default_dns_v6.lock() = v6;
    }

    pub fn get_default_dns_v6(&self) -> Ipv6Address {
        *self.default_dns_v6.lock()
    }

    /*
     * Generates an IPv6 link-local address from the interface MAC using EUI-64.
     * The result is fe80::xxxx:xxff:fexx:xxxx where x comes from the MAC.
     * The 7th bit of the first MAC byte is flipped per RFC 4291.
     */
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
