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
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use smoltcp::socket::raw::{self, PacketBuffer as RawPacketBuffer, PacketMetadata as RawPacketMetadata};
use smoltcp::wire::{IpVersion, IpProtocol};

use super::super::core::NetworkStack;
use super::super::device::now_ms;
use super::super::util::icmp_checksum;
use super::types::PingResult;

static PING_WAITING: AtomicBool = AtomicBool::new(false);
static PING_TARGET: spin::Mutex<[u8; 4]> = spin::Mutex::new([0; 4]);
static PING_SEQ: AtomicU16 = AtomicU16::new(0);
static PING_REPLY_RECEIVED: AtomicBool = AtomicBool::new(false);
static PING_REPLY_TIME: AtomicU64 = AtomicU64::new(0);
static PING_SEND_TIME: AtomicU64 = AtomicU64::new(0);

impl NetworkStack {
    pub fn ping(&self, target: [u8; 4], seq: u16, timeout_ms: u64) -> PingResult {
        PING_WAITING.store(true, Ordering::SeqCst);
        *PING_TARGET.lock() = target;
        PING_SEQ.store(seq, Ordering::SeqCst);
        PING_REPLY_RECEIVED.store(false, Ordering::SeqCst);

        let send_time = now_ms();
        PING_SEND_TIME.store(send_time, Ordering::SeqCst);

        if self.send_icmp_echo_via_raw(target, seq).is_err() {
            PING_WAITING.store(false, Ordering::SeqCst);
            return PingResult { success: false, rtt_ms: 0, seq };
        }

        let deadline = send_time + timeout_ms;
        let mut poll_count = 0u32;

        while now_ms() < deadline {
            self.poll();

            if self.check_icmp_reply_via_raw(target, seq) {
                let rtt = PING_REPLY_TIME.load(Ordering::SeqCst).saturating_sub(send_time);
                PING_WAITING.store(false, Ordering::SeqCst);
                return PingResult { success: true, rtt_ms: rtt, seq };
            }

            poll_count += 1;

            if poll_count % 10 == 0 {
                x86_64::instructions::interrupts::enable();
                for _ in 0..1000 { core::hint::spin_loop(); }
                x86_64::instructions::interrupts::disable();
            } else {
                for _ in 0..100 { core::hint::spin_loop(); }
            }

            if poll_count > 5000 {
                break;
            }
        }

        PING_WAITING.store(false, Ordering::SeqCst);
        PingResult { success: false, rtt_ms: 0, seq }
    }

    pub(super) fn send_icmp_echo_via_raw(&self, target: [u8; 4], seq: u16) -> Result<(), &'static str> {
        let our_ip = self.get_ipv4_config().map(|(ip, _)| ip).unwrap_or([10, 0, 2, 15]);

        let mut sockets = self.sockets.lock();
        let rx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
        let tx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
        let raw_socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::Icmp, rx, tx);
        let handle = sockets.add(raw_socket);

        let identifier = 0x4E4Fu16;
        let payload = b"NONOS ICMP PING";

        let mut icmp_pkt = Vec::with_capacity(8 + payload.len());
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
        let mut ip_pkt = Vec::with_capacity(total_len);
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
            let s: &mut raw::Socket = sockets.get_mut(handle);
            s.send_slice(&ip_pkt).map_err(|_| "ping send failed")?;
        }

        sockets.remove(handle);

        let mut stats = self.stats.lock();
        stats.tx_packets += 1;
        stats.tx_bytes += ip_pkt.len() as u64;

        Ok(())
    }

    pub(super) fn check_icmp_reply_via_raw(&self, target: [u8; 4], expected_seq: u16) -> bool {
        if !PING_WAITING.load(Ordering::SeqCst) {
            return false;
        }

        let mut sockets = self.sockets.lock();
        let rx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
        let tx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 256]);
        let raw_socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::Icmp, rx, tx);
        let handle = sockets.add(raw_socket);

        self.poll_interface();

        let s: &mut raw::Socket = sockets.get_mut(handle);
        let mut found = false;

        while s.can_recv() {
            let mut buf = [0u8; 128];
            if let Ok(n) = s.recv_slice(&mut buf) {
                if n >= 28 {
                    let ip_hdr_len = ((buf[0] & 0x0F) as usize) * 4;
                    if n >= ip_hdr_len + 8 {
                        let src_ip = [buf[12], buf[13], buf[14], buf[15]];
                        if src_ip == target {
                            let icmp = &buf[ip_hdr_len..];
                            if icmp[0] == 0 {
                                let id = u16::from_be_bytes([icmp[4], icmp[5]]);
                                let recv_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                                if id == 0x4E4F && recv_seq == expected_seq {
                                    PING_REPLY_TIME.store(now_ms(), Ordering::SeqCst);
                                    PING_REPLY_RECEIVED.store(true, Ordering::SeqCst);
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }

        sockets.remove(handle);

        if found {
            let mut stats = self.stats.lock();
            stats.rx_packets += 1;
        }

        found
    }
}
