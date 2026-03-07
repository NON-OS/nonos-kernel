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
 * Socket and connection tracking for the network stack.
 *
 * Provides introspection into active TCP connections and ARP cache state.
 * Used by network monitoring tools and the netstat shell command.
 *
 * ARP cache is bounded to MAX_ARP_ENTRIES to prevent memory exhaustion
 * from ARP flooding attacks. Old entries are evicted FIFO when full.
 */

use alloc::vec::Vec;
use spin::Mutex;

use smoltcp::{
    socket::tcp,
    wire::IpAddress as SmolIpAddress,
};

use super::core::NetworkStack;
use super::types::{ArpEntry, SocketInfo};

static ARP_CACHE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new());

const MAX_ARP_ENTRIES: usize = 64;

impl NetworkStack {
    pub fn get_mac_address(&self) -> [u8; 6] {
        let iface = self.iface.lock();
        let smoltcp::wire::HardwareAddress::Ethernet(eth) = iface.hardware_addr();
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

    pub(crate) fn pick_single_active_conn(&self) -> Option<u32> {
        let conns = self.conns.lock();
        let mut last: Option<u32> = None;
        for (id, c) in conns.iter() {
            if !c.closed {
                last = Some(*id);
            }
        }
        if conns.iter().filter(|(_, c)| !c.closed).count() == 1 {
            last
        } else {
            None
        }
    }
}
