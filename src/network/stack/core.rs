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
 * Core network stack implementation.
 *
 * Built on smoltcp, a user-space TCP/IP stack. Provides the central
 * NetworkStack singleton that manages:
 * - Interface polling for packet processing
 * - Socket set for TCP connections
 * - Connection tracking for application-level handles
 * - Network statistics collection
 *
 * Initialize with init_network_stack() early in boot, then access
 * via get_network_stack() from anywhere in the kernel.
 */

use alloc::collections::BTreeMap;
use alloc::vec;
use core::sync::atomic::AtomicU32;
use spin::{Mutex, Once};

use smoltcp::{
    iface::{Config as IfaceConfig, Interface, Routes, SocketSet},
    time::Instant as SmolInstant,
    wire::{
        EthernetAddress, HardwareAddress, IpAddress as SmolIpAddress, IpCidr,
        Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address,
    },
};

use super::device::{now_ms, SmolDeviceAdapter, DEFAULT_MAC};
use super::types::{ConnectionEntry, Ipv4Address, Ipv6Address, NetworkStats};

static STACK: Once<NetworkStack> = Once::new();

const DEFAULT_DNS_V6: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
];

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

pub fn init_network_stack() {
    STACK.call_once(|| {
        let mut dev = SmolDeviceAdapter;
        let mut cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(DEFAULT_MAC)));
        cfg.random_seed = 0xD1E5_7A2C;
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(now_ms() as i64));

        let _ = iface.update_ip_addrs(|ips| {
            let _ = ips.push(IpCidr::new(
                SmolIpAddress::Ipv4(SmolIpv4Address::new(127, 0, 0, 1)),
                8,
            ));
            let _ = ips.push(IpCidr::new(
                SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK),
                128,
            ));
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
    /*
     * Drives the smoltcp interface forward. Call this frequently to
     * process incoming packets and transmit queued data. Should be
     * invoked from the network polling loop or timer interrupt.
     */
    #[inline]
    pub fn poll_interface(&self) {
        let ts = SmolInstant::from_millis(now_ms() as i64);
        let mut iface = self.iface.lock();
        let mut sockets = self.sockets.lock();
        let _ = iface.poll(ts, &mut SmolDeviceAdapter, &mut *sockets);
    }

    #[inline]
    pub(crate) fn poll(&self) {
        self.poll_interface();
    }
}
