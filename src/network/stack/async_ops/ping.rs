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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::Mutex;
use smoltcp::socket::raw::{self, PacketBuffer as RawPacketBuffer, PacketMetadata as RawPacketMetadata};
use smoltcp::wire::{IpVersion, IpProtocol};
use super::AsyncResult;
use super::super::core::get_network_stack;
use super::super::device::now_ms;
use super::super::util::icmp_checksum;

static PING_ACTIVE: AtomicBool = AtomicBool::new(false);
static PING_TARGET: Mutex<[u8; 4]> = Mutex::new([0; 4]);
static PING_SEQ: AtomicU32 = AtomicU32::new(0);
static PING_START: AtomicU64 = AtomicU64::new(0);
static PING_TIMEOUT: AtomicU64 = AtomicU64::new(300);
static PING_REPLY_RECEIVED: AtomicBool = AtomicBool::new(false);
static PING_RTT: AtomicU64 = AtomicU64::new(0);
static PING_RAW_HANDLE: Mutex<Option<smoltcp::iface::SocketHandle>> = Mutex::new(None);
static PING_POLL_COUNT: AtomicU64 = AtomicU64::new(0);
const PING_MAX_POLLS: u64 = 50;

pub fn ping_start(target: [u8; 4], seq: u16, timeout_ms: u64) -> Result<(), &'static str> {
    if PING_ACTIVE.load(Ordering::SeqCst) {
        return Err("ping already active");
    }

    let ns = get_network_stack().ok_or("no network stack")?;
    let our_ip = ns.get_ipv4_config().map(|(ip, _)| ip).unwrap_or([10, 0, 2, 15]);

    let mut sockets = ns.sockets.lock();
    let rx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
    let tx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
    let raw_socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::Icmp, rx, tx);
    let handle = sockets.add(raw_socket);
    drop(sockets);

    let identifier = 0x4E4Fu16;
    let payload = b"NONOS";

    let mut icmp_pkt = alloc::vec::Vec::with_capacity(8 + payload.len());
    icmp_pkt.push(8u8);
    icmp_pkt.push(0u8);
    icmp_pkt.push(0);
    icmp_pkt.push(0);
    icmp_pkt.extend_from_slice(&identifier.to_be_bytes());
    icmp_pkt.extend_from_slice(&seq.to_be_bytes());
    icmp_pkt.extend_from_slice(payload);

    let checksum = icmp_checksum(&icmp_pkt);
    icmp_pkt[2] = (checksum >> 8) as u8;
    icmp_pkt[3] = (checksum & 0xFF) as u8;

    let total_len = 20 + icmp_pkt.len();
    let mut ip_pkt = alloc::vec::Vec::with_capacity(total_len);
    ip_pkt.push(0x45);
    ip_pkt.push(0x00);
    ip_pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip_pkt.extend_from_slice(&0x4E4Fu16.to_be_bytes());
    ip_pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    ip_pkt.push(64);
    ip_pkt.push(1);
    ip_pkt.push(0);
    ip_pkt.push(0);
    ip_pkt.extend_from_slice(&our_ip);
    ip_pkt.extend_from_slice(&target);

    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i != 10 {
            sum += u16::from_be_bytes([ip_pkt[i], ip_pkt[i + 1]]) as u32;
        }
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    let cksum = !(sum as u16);
    ip_pkt[10] = (cksum >> 8) as u8;
    ip_pkt[11] = (cksum & 0xFF) as u8;

    ip_pkt.extend_from_slice(&icmp_pkt);

    {
        let mut sockets = ns.sockets.lock();
        let s: &mut raw::Socket = sockets.get_mut(handle);
        s.send_slice(&ip_pkt).map_err(|_| "ping send failed")?;
    }

    ns.poll();

    *PING_RAW_HANDLE.lock() = Some(handle);
    *PING_TARGET.lock() = target;
    PING_SEQ.store(seq as u32, Ordering::SeqCst);
    PING_START.store(now_ms(), Ordering::SeqCst);
    PING_TIMEOUT.store(timeout_ms, Ordering::SeqCst);
    PING_REPLY_RECEIVED.store(false, Ordering::SeqCst);
    PING_POLL_COUNT.store(0, Ordering::SeqCst);
    PING_ACTIVE.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn ping_poll() -> AsyncResult<u64> {
    if !PING_ACTIVE.load(Ordering::SeqCst) {
        if PING_REPLY_RECEIVED.load(Ordering::SeqCst) {
            return AsyncResult::Ready(PING_RTT.load(Ordering::SeqCst));
        }
        return AsyncResult::Error("no ping active");
    }

    let elapsed = now_ms().saturating_sub(PING_START.load(Ordering::SeqCst));
    let polls = PING_POLL_COUNT.fetch_add(1, Ordering::SeqCst);
    if elapsed > PING_TIMEOUT.load(Ordering::SeqCst) || polls > PING_MAX_POLLS {
        ping_cleanup();
        return AsyncResult::Error("timeout");
    }

    let ns = match get_network_stack() {
        Some(s) => s,
        None => {
            ping_cleanup();
            return AsyncResult::Error("no network");
        }
    };

    ns.poll();

    let handle = match *PING_RAW_HANDLE.lock() {
        Some(h) => h,
        None => {
            ping_cleanup();
            return AsyncResult::Error("no ping handle");
        }
    };

    let mut sockets = ns.sockets.lock();
    let s: &mut raw::Socket = sockets.get_mut(handle);

    if s.can_recv() {
        let mut buf = [0u8; 128];
        if let Ok(n) = s.recv_slice(&mut buf) {
            if n >= 28 {
                let ip_hdr_len = ((buf[0] & 0x0F) as usize) * 4;
                if n >= ip_hdr_len + 8 {
                    let icmp = &buf[ip_hdr_len..];
                    if icmp[0] == 0 {
                        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
                        let recv_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                        if id == 0x4E4F && recv_seq as u32 == PING_SEQ.load(Ordering::SeqCst) {
                            let rtt = now_ms().saturating_sub(PING_START.load(Ordering::SeqCst));
                            PING_RTT.store(rtt, Ordering::SeqCst);
                            PING_REPLY_RECEIVED.store(true, Ordering::SeqCst);
                            drop(sockets);
                            ping_cleanup();
                            return AsyncResult::Ready(rtt);
                        }
                    }
                }
            }
        }
    }

    AsyncResult::Pending
}

fn ping_cleanup() {
    if let Some(handle) = PING_RAW_HANDLE.lock().take() {
        if let Some(ns) = get_network_stack() {
            ns.sockets.lock().remove(handle);
        }
    }
    PING_ACTIVE.store(false, Ordering::SeqCst);
}

pub fn ping_is_active() -> bool {
    PING_ACTIVE.load(Ordering::SeqCst)
}

pub fn ping_cancel() {
    ping_cleanup();
}
