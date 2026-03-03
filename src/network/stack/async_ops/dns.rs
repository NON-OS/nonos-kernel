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

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata};
use smoltcp::wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address, IpEndpoint};
use super::AsyncResult;
use super::super::core::get_network_stack;
use super::super::device::now_ms;
use super::super::dns_impl::{build_dns_query, parse_dns_response_a};

static DNS_QUERY_ACTIVE: AtomicBool = AtomicBool::new(false);
static DNS_QUERY_START: AtomicU64 = AtomicU64::new(0);
static DNS_QUERY_SENT: AtomicBool = AtomicBool::new(false);
static DNS_RESULT: Mutex<Option<Vec<[u8; 4]>>> = Mutex::new(None);
static DNS_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
static DNS_HANDLE: Mutex<Option<smoltcp::iface::SocketHandle>> = Mutex::new(None);

pub fn dns_start_query(hostname: &str) -> Result<(), &'static str> {
    if DNS_QUERY_ACTIVE.load(Ordering::SeqCst) {
        return Err("dns query already in progress");
    }

    let ns = get_network_stack().ok_or("no network stack")?;

    let mut sockets = ns.sockets.lock();
    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 1024]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 1024]);
    let handle = sockets.add(udp::Socket::new(rx, tx));

    let server = *ns.default_dns_v4.lock();
    let query = build_dns_query(hostname);

    {
        let s: &mut udp::Socket = sockets.get_mut(handle);
        s.bind(0).map_err(|_| "dns bind failed")?;
        let endpoint = IpEndpoint::new(
            SmolIpAddress::Ipv4(SmolIpv4Address::new(server[0], server[1], server[2], server[3])),
            53
        );
        let metadata = smoltcp::socket::udp::UdpMetadata::from(endpoint);
        s.send_slice(&query, metadata).map_err(|_| "dns send failed")?;
    }
    drop(sockets);

    *DNS_HANDLE.lock() = Some(handle);
    *DNS_RESULT.lock() = None;
    *DNS_ERROR.lock() = None;
    DNS_QUERY_START.store(now_ms(), Ordering::SeqCst);
    DNS_QUERY_SENT.store(true, Ordering::SeqCst);
    DNS_QUERY_ACTIVE.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn dns_poll() -> AsyncResult<[u8; 4]> {
    if !DNS_QUERY_ACTIVE.load(Ordering::SeqCst) {
        if let Some(addrs) = DNS_RESULT.lock().as_ref() {
            if let Some(ip) = addrs.first() {
                return AsyncResult::Ready(*ip);
            }
        }
        if let Some(e) = *DNS_ERROR.lock() {
            return AsyncResult::Error(e);
        }
        return AsyncResult::Error("no dns query active");
    }

    let elapsed = now_ms().saturating_sub(DNS_QUERY_START.load(Ordering::SeqCst));
    if elapsed > 2000 {
        dns_cleanup();
        *DNS_ERROR.lock() = Some("dns timeout");
        return AsyncResult::Error("dns timeout");
    }

    let ns = match get_network_stack() {
        Some(s) => s,
        None => {
            dns_cleanup();
            return AsyncResult::Error("no network");
        }
    };

    ns.poll();

    let handle = match *DNS_HANDLE.lock() {
        Some(h) => h,
        None => {
            dns_cleanup();
            return AsyncResult::Error("no dns handle");
        }
    };

    let mut sockets = ns.sockets.lock();
    let s: &mut udp::Socket = sockets.get_mut(handle);

    if let Ok((data, _ep)) = s.recv() {
        match parse_dns_response_a(data) {
            Ok(addrs) => {
                drop(sockets);
                if let Some(ip) = addrs.first() {
                    let ip = *ip;
                    *DNS_RESULT.lock() = Some(addrs);
                    dns_cleanup();
                    return AsyncResult::Ready(ip);
                } else {
                    dns_cleanup();
                    *DNS_ERROR.lock() = Some("no dns records");
                    return AsyncResult::Error("no dns records");
                }
            }
            Err(e) => {
                drop(sockets);
                dns_cleanup();
                *DNS_ERROR.lock() = Some(e);
                return AsyncResult::Error(e);
            }
        }
    }

    AsyncResult::Pending
}

fn dns_cleanup() {
    if let Some(handle) = DNS_HANDLE.lock().take() {
        if let Some(ns) = get_network_stack() {
            let mut sockets = ns.sockets.lock();
            sockets.remove(handle);
        }
    }
    DNS_QUERY_ACTIVE.store(false, Ordering::SeqCst);
    DNS_QUERY_SENT.store(false, Ordering::SeqCst);
}

pub fn dns_cancel() {
    dns_cleanup();
}
