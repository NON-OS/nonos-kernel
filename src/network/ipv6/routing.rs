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
use super::address::{Ipv6Address, Ipv6Cidr};
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct Ipv6Route {
    pub destination: Ipv6Cidr,
    pub gateway: Option<Ipv6Address>,
    pub interface: u32,
    pub metric: u32,
    pub flags: u32,
    pub expires: Option<u64>,
}

pub const RTF_UP: u32 = 0x0001;
pub const RTF_GATEWAY: u32 = 0x0002;
pub const RTF_HOST: u32 = 0x0004;
pub const RTF_DEFAULT: u32 = 0x0008;

pub struct Ipv6RoutingTable {
    routes: Vec<Ipv6Route>,
}

static ROUTING_TABLE: Mutex<Ipv6RoutingTable> = Mutex::new(Ipv6RoutingTable { routes: Vec::new() });

impl Ipv6RoutingTable {
    pub fn add(&mut self, route: Ipv6Route) {
        self.routes.retain(|r| r.destination != route.destination || r.gateway != route.gateway);
        self.routes.push(route);
        self.routes.sort_by(|a, b| b.destination.prefix_len.cmp(&a.destination.prefix_len));
    }

    pub fn remove(&mut self, dest: &Ipv6Cidr) {
        self.routes.retain(|r| &r.destination != dest);
    }

    pub fn lookup(&self, addr: &Ipv6Address) -> Option<&Ipv6Route> {
        let now = crate::sys::clock::uptime_ms();
        self.routes.iter().find(|r| {
            if let Some(exp) = r.expires {
                if now > exp {
                    return false;
                }
            }
            r.destination.contains(addr) && (r.flags & RTF_UP) != 0
        })
    }

    pub fn default_gateway(&self) -> Option<Ipv6Address> {
        self.routes
            .iter()
            .find(|r| (r.flags & RTF_DEFAULT) != 0 && r.gateway.is_some())
            .and_then(|r| r.gateway)
    }

    pub fn routes(&self) -> &[Ipv6Route] {
        &self.routes
    }

    pub fn expire_routes(&mut self) {
        let now = crate::sys::clock::uptime_ms();
        self.routes.retain(|r| r.expires.map(|e| now <= e).unwrap_or(true));
    }
}

pub fn add_route(dest: Ipv6Cidr, gateway: Option<Ipv6Address>, iface: u32, metric: u32) {
    let flags = RTF_UP
        | if gateway.is_some() { RTF_GATEWAY } else { 0 }
        | if dest.prefix_len == 128 { RTF_HOST } else { 0 }
        | if dest.address.is_unspecified() && dest.prefix_len == 0 { RTF_DEFAULT } else { 0 };
    ROUTING_TABLE.lock().add(Ipv6Route {
        destination: dest,
        gateway,
        interface: iface,
        metric,
        flags,
        expires: None,
    });
}

pub fn lookup_route(addr: &Ipv6Address) -> Option<Ipv6Route> {
    ROUTING_TABLE.lock().lookup(addr).cloned()
}

pub fn get_default_gateway() -> Option<Ipv6Address> {
    ROUTING_TABLE.lock().default_gateway()
}

pub fn add_default_route(gateway: Ipv6Address, iface: u32) {
    add_route(Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0), Some(gateway), iface, 1024);
}

pub fn get_interface_for_addr(addr: &Ipv6Address) -> Option<u32> {
    ROUTING_TABLE.lock().lookup(addr).map(|r| r.interface)
}
