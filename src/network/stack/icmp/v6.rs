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

use smoltcp::socket::raw::{self, PacketBuffer as RawPacketBuffer, PacketMetadata as RawPacketMetadata};
use smoltcp::wire::{IpVersion, IpProtocol};

use super::super::core::NetworkStack;
use super::super::device::now_ms;
use super::types::PingResult;

fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }

    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }

    let len = icmp_data.len() as u32;
    sum += (len >> 16) as u32;
    sum += (len & 0xFFFF) as u32;

    sum += 58u32;

    for i in (0..icmp_data.len()).step_by(2) {
        if i == 2 {
            continue;
        }
        let byte1 = icmp_data[i];
        let byte2 = if i + 1 < icmp_data.len() { icmp_data[i + 1] } else { 0 };
        sum += u16::from_be_bytes([byte1, byte2]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

impl NetworkStack {
    pub fn ping6(&self, target: [u8; 16], seq: u16, timeout_ms: u64) -> PingResult {
        let send_time = now_ms();

        if self.send_icmpv6_echo(target, seq).is_err() {
            return PingResult { success: false, rtt_ms: 0, seq };
        }

        let deadline = send_time + timeout_ms;
        let mut poll_count = 0u32;

        while now_ms() < deadline {
            self.poll();

            if let Some(rtt) = self.check_icmpv6_reply(target, seq, send_time) {
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

        PingResult { success: false, rtt_ms: 0, seq }
    }

    fn send_icmpv6_echo(&self, target: [u8; 16], seq: u16) -> Result<(), &'static str> {
        let our_ip = self.get_ipv6_config().map(|(ip, _)| ip)
            .unwrap_or_else(|| self.generate_link_local_v6());

        let mut sockets = self.sockets.lock();
        let rx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 512]);
        let tx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 512]);
        let raw_socket = raw::Socket::new(IpVersion::Ipv6, IpProtocol::Icmpv6, rx, tx);
        let handle = sockets.add(raw_socket);

        let identifier = 0x4E4Fu16;
        let payload = b"NONOS ICMPv6 PING";

        let mut icmp_pkt = Vec::with_capacity(8 + payload.len());
        icmp_pkt.push(128u8);
        icmp_pkt.push(0u8);
        icmp_pkt.push(0);
        icmp_pkt.push(0);
        icmp_pkt.extend_from_slice(&identifier.to_be_bytes());
        icmp_pkt.extend_from_slice(&seq.to_be_bytes());
        icmp_pkt.extend_from_slice(payload);

        let checksum = icmpv6_checksum(&our_ip, &target, &icmp_pkt);
        icmp_pkt[2] = (checksum >> 8) as u8;
        icmp_pkt[3] = (checksum & 0xFF) as u8;

        let payload_len = icmp_pkt.len() as u16;
        let mut ip_pkt = Vec::with_capacity(40 + icmp_pkt.len());

        ip_pkt.push(0x60);
        ip_pkt.push(0x00);
        ip_pkt.push(0x00);
        ip_pkt.push(0x00);
        ip_pkt.extend_from_slice(&payload_len.to_be_bytes());
        ip_pkt.push(58);
        ip_pkt.push(64);
        ip_pkt.extend_from_slice(&our_ip);
        ip_pkt.extend_from_slice(&target);
        ip_pkt.extend_from_slice(&icmp_pkt);

        {
            let s: &mut raw::Socket = sockets.get_mut(handle);
            s.send_slice(&ip_pkt).map_err(|_| "ping6 send failed")?;
        }

        sockets.remove(handle);

        let mut stats = self.stats.lock();
        stats.tx_packets += 1;
        stats.tx_bytes += ip_pkt.len() as u64;

        Ok(())
    }

    fn check_icmpv6_reply(&self, target: [u8; 16], expected_seq: u16, send_time: u64) -> Option<u64> {
        let mut sockets = self.sockets.lock();
        let rx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 512]);
        let tx = RawPacketBuffer::new(vec![RawPacketMetadata::EMPTY; 4], vec![0; 512]);
        let raw_socket = raw::Socket::new(IpVersion::Ipv6, IpProtocol::Icmpv6, rx, tx);
        let handle = sockets.add(raw_socket);

        self.poll_interface();

        let s: &mut raw::Socket = sockets.get_mut(handle);
        let mut result = None;

        while s.can_recv() {
            let mut buf = [0u8; 256];
            if let Ok(n) = s.recv_slice(&mut buf) {
                if n >= 48 {
                    let src_ip: [u8; 16] = buf[8..24].try_into().ok()?;
                    if src_ip == target {
                        let icmp = &buf[40..];
                        if icmp[0] == 129 && icmp[1] == 0 {
                            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
                            let recv_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                            if id == 0x4E4F && recv_seq == expected_seq {
                                let rtt = now_ms().saturating_sub(send_time);
                                result = Some(rtt);

                                let mut stats = self.stats.lock();
                                stats.rx_packets += 1;
                                break;
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }

        sockets.remove(handle);
        result
    }

    pub fn ping_ip(&self, addr: crate::network::ip::IpAddress, seq: u16, timeout_ms: u64) -> PingResult {
        match addr {
            crate::network::ip::IpAddress::V4(v4) => self.ping(v4, seq, timeout_ms),
            crate::network::ip::IpAddress::V6(v6) => self.ping6(v6, seq, timeout_ms),
        }
    }
}
