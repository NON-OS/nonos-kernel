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

use super::super::core::get_network_stack;
use super::super::device::now_ms;
use super::super::dns_impl::{build_dns_query, parse_dns_response_a};
use super::AsyncResult;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata};
use smoltcp::wire::{IpAddress as SmolIpAddress, IpEndpoint, Ipv4Address as SmolIpv4Address};
use spin::Mutex;

static DNS_QUERY_ACTIVE: AtomicBool = AtomicBool::new(false);
static DNS_QUERY_START: AtomicU64 = AtomicU64::new(0);
static DNS_QUERY_SENT: AtomicBool = AtomicBool::new(false);
static DNS_RESULT: Mutex<Option<Vec<[u8; 4]>>> = Mutex::new(None);
static DNS_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
static DNS_HANDLE: Mutex<Option<smoltcp::iface::SocketHandle>> = Mutex::new(None);
static DNS_HOSTNAME: Mutex<Option<String>> = Mutex::new(None);
static DNS_RETRY_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn dns_start_query(hostname: &str) -> Result<(), &'static str> {
    crate::sys::serial::println(b"[DNS] starting query");
    if DNS_QUERY_ACTIVE.load(Ordering::SeqCst) {
        return Err("dns query already in progress");
    }

    let ns = get_network_stack().ok_or("no network stack")?;
    ns.poll();

    let (ip, _) = ns.get_ipv4_config().ok_or("no ipv4 address")?;
    if ip[0] == 127 || ip == [0, 0, 0, 0] {
        return Err("no routable ip");
    }

    let mut sockets = ns.sockets.lock();
    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
    let handle = sockets.add(udp::Socket::new(rx, tx));

    let server = *ns.default_dns_v4.lock();
    let query = build_dns_query(hostname);

    {
        let s: &mut udp::Socket = sockets.get_mut(handle);
        let ephemeral_port = 49152 + ((now_ms() as u16) % 16383);
        s.bind(ephemeral_port).map_err(|_| "dns bind failed")?;
        let remote = IpEndpoint::new(
            SmolIpAddress::Ipv4(SmolIpv4Address::new(server[0], server[1], server[2], server[3])),
            53,
        );
        s.send_slice(&query, smoltcp::socket::udp::UdpMetadata::from(remote))
            .map_err(|_| "dns send failed")?;
    }
    drop(sockets);

    *DNS_HANDLE.lock() = Some(handle);
    *DNS_HOSTNAME.lock() = Some(String::from(hostname));
    *DNS_RESULT.lock() = None;
    *DNS_ERROR.lock() = None;
    DNS_RETRY_COUNT.store(0, Ordering::SeqCst);
    DNS_QUERY_START.store(now_ms(), Ordering::SeqCst);
    DNS_QUERY_SENT.store(true, Ordering::SeqCst);
    DNS_QUERY_ACTIVE.store(true, Ordering::SeqCst);

    // Reset poll counter for clean per-query logging
    DNS_POLL_COUNT.store(0, Ordering::Relaxed);

    // Flush the DNS query immediately — mirrors the sync path which calls
    // self.poll() in a tight loop right after enqueuing the query.
    crate::sys::serial::println(b"[DNS] flushing query via ns.poll()");
    ns.poll();
    crate::sys::serial::println(b"[DNS] ns.poll() returned, query active");

    Ok(())
}

static DNS_POLL_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn dns_poll() -> AsyncResult<[u8; 4]> {
    let count = DNS_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if count == 0 || count % 2000 == 0 { crate::sys::serial::println(b"[DNS] polling..."); }
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

    let current_time = now_ms();
    let start_time = DNS_QUERY_START.load(Ordering::SeqCst);
    let elapsed = current_time.saturating_sub(start_time);
    let count = DNS_POLL_COUNT.load(Ordering::Relaxed);
    if count % 2000 == 1 {
        crate::sys::serial::print(b"[DNS] now=");
        crate::sys::serial::print_dec(current_time);
        crate::sys::serial::print(b" start=");
        crate::sys::serial::print_dec(start_time);
        crate::sys::serial::print(b" elapsed=");
        crate::sys::serial::print_dec(elapsed);
        crate::sys::serial::println(b"");
    }
    /* 10s timeout - 2s was too aggressive for slow/congested networks */
    if elapsed > 10_000 {
        crate::sys::serial::println(b"[DNS] TIMEOUT!");
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

    match s.recv() {
        Ok((data, _ep)) => {
            crate::sys::serial::print(b"[DNS] recv OK len=");
            crate::sys::serial::print_dec(data.len() as u64);
            crate::sys::serial::println(b"");
            match parse_dns_response_a(data) {
                Ok(addrs) => {
                    drop(sockets);
                    if let Some(ip) = addrs.first() {
                        let ip = *ip;
                        crate::sys::serial::print(b"[DNS] resolved ");
                        crate::sys::serial::print_dec(ip[0] as u64);
                        crate::sys::serial::print(b".");
                        crate::sys::serial::print_dec(ip[1] as u64);
                        crate::sys::serial::print(b".");
                        crate::sys::serial::print_dec(ip[2] as u64);
                        crate::sys::serial::print(b".");
                        crate::sys::serial::print_dec(ip[3] as u64);
                        crate::sys::serial::println(b"");
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
                    crate::sys::serial::println(b"[DNS] parse error");
                    drop(sockets);
                    dns_cleanup();
                    *DNS_ERROR.lock() = Some(e);
                    return AsyncResult::Error(e);
                }
            }
        }
        Err(_) => {
            let retries = DNS_RETRY_COUNT.load(Ordering::Relaxed);
            if retries < 2 && elapsed >= 2500 * (retries as u64 + 1) {
                if let Some(hostname) = DNS_HOSTNAME.lock().as_ref() {
                    let server = *ns.default_dns_v4.lock();
                    let query = build_dns_query(hostname);
                    let remote = IpEndpoint::new(
                        SmolIpAddress::Ipv4(SmolIpv4Address::new(server[0], server[1], server[2], server[3])),
                        53
                    );
                    if s.send_slice(&query, smoltcp::socket::udp::UdpMetadata::from(remote)).is_ok() {
                        DNS_RETRY_COUNT.fetch_add(1, Ordering::Relaxed);
                        crate::sys::serial::print(b"[DNS] retransmit #");
                        crate::sys::serial::print_dec((retries + 1) as u64);
                        crate::sys::serial::println(b"");
                    }
                }
            }
            if count == 1 || count % 4000 == 0 {
                crate::sys::serial::print(b"[DNS] no recv yet, polls=");
                crate::sys::serial::print_dec(count as u64);
                crate::sys::serial::print(b" can_recv=");
                if s.can_recv() {
                    crate::sys::serial::println(b"true");
                } else {
                    crate::sys::serial::println(b"false");
                }
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
    *DNS_HOSTNAME.lock() = None;
    DNS_RETRY_COUNT.store(0, Ordering::SeqCst);
    DNS_QUERY_ACTIVE.store(false, Ordering::SeqCst);
    DNS_QUERY_SENT.store(false, Ordering::SeqCst);
}

pub fn dns_cancel() {
    dns_cleanup();
}
