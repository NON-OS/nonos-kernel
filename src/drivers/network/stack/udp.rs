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
use alloc::sync::Arc;
use core::mem;
use spin::Mutex;

use super::arp::{arp_lookup, send_arp_request};
use super::filter::run_send;
use super::headers::{
    ip_checksum, to_be16, udp_checksum, ETH_HDR, ET_IPV4, IP_PROTO_UDP, Ipv4Header, UdpHeader,
};
use super::interface::{get_default_interface, get_ipv4};

pub type UdpHandler = Arc<dyn Fn(&[u8], [u8; 4], u16) + Send + Sync>;
pub(super) static UDP_LISTENERS: Mutex<BTreeMap<u16, UdpHandler>> = Mutex::new(BTreeMap::new());

pub fn udp_listen(port: u16, handler: UdpHandler) {
    UDP_LISTENERS.lock().insert(port, handler);
}

pub fn udp_send(
    dst_ip: [u8; 4],
    dst_port: u16,
    src_port: u16,
    payload: &[u8],
) -> Result<(), &'static str> {
    let iface = get_default_interface().ok_or("no default iface")?;
    let src_mac = iface.get_mac_address();
    let dst_mac = if let Some(m) = arp_lookup(dst_ip) {
        m
    } else {
        let _ = send_arp_request(dst_ip);
        return Err("ARP unresolved");
    };
    let src_ip = get_ipv4();
    let mtu = iface.mtu();
    let overhead = ETH_HDR + 20 + 8;
    if payload.len() + overhead > mtu {
        return Err("payload exceeds MTU");
    }
    let total = overhead + payload.len();
    let mut frame = alloc::vec![0u8; total];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&to_be16(ET_IPV4));
    let ip_off = ETH_HDR;
    {
        let hdr = Ipv4Header {
            vihl: (4 << 4) | 5,
            dscp_ecn: 0,
            total_len_be: (20u16 + 8 + payload.len() as u16).to_be_bytes(),
            id_be: 0u16.to_be_bytes(),
            flags_frag_be: 0u16.to_be_bytes(),
            ttl: 64,
            proto: IP_PROTO_UDP,
            hdr_checksum_be: [0, 0],
            src: src_ip,
            dst: dst_ip,
        };
        // SAFETY: frame buffer is properly sized, ip_off is within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                frame.as_mut_ptr().add(ip_off),
                mem::size_of::<Ipv4Header>(),
            );
        }
        // SAFETY: frame contains valid Ipv4Header at ip_off, using read_unaligned for packed struct.
        let ip_hdr: Ipv4Header =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(ip_off) as *const Ipv4Header) };
        let c = ip_checksum(&ip_hdr);
        let checksum_bytes = c.to_be_bytes();
        frame[ip_off + 10] = checksum_bytes[0];
        frame[ip_off + 11] = checksum_bytes[1];
    }
    let udp_off = ip_off + 20;
    {
        let hdr = UdpHeader {
            sport_be: src_port.to_be_bytes(),
            dport_be: dst_port.to_be_bytes(),
            len_be: (8 + payload.len() as u16).to_be_bytes(),
            csum_be: [0, 0],
        };
        // SAFETY: frame buffer is properly sized, udp_off is within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                frame.as_mut_ptr().add(udp_off),
                mem::size_of::<UdpHeader>(),
            );
        }
        frame[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);
        // SAFETY: frame contains valid headers, using read_unaligned for packed structs.
        let udp_hdr: UdpHeader =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(udp_off) as *const UdpHeader) };
        let ip_hdr: Ipv4Header =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(ip_off) as *const Ipv4Header) };
        let c = udp_checksum(&ip_hdr, &udp_hdr, &frame[udp_off + 8..]);
        let checksum_bytes = c.to_be_bytes();
        frame[udp_off + 6] = checksum_bytes[0];
        frame[udp_off + 7] = checksum_bytes[1];
    }
    if !run_send(&frame) {
        return Err("send filtered");
    }
    iface.send_packet(&frame)
}
