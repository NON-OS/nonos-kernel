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

use super::arp::handle_arp;
use super::filter::{run_post, run_pre, run_send};
use super::headers::{be16, EthHeader, ETH_HDR, ET_ARP, ET_IPV4, IP_PROTO_UDP, Ipv4Header, UdpHeader};
use super::interface::get_default_interface;
use super::udp::UDP_LISTENERS;

pub fn receive_packet(frame: &[u8]) -> Result<(), &'static str> {
    if !run_pre(frame) {
        return Err("filtered pre-recv");
    }
    if frame.len() < ETH_HDR {
        return Err("frame too short");
    }
    let mut eth = EthHeader {
        dst: [0; 6],
        src: [0; 6],
        et_be: [0; 2],
    };
    eth.dst.copy_from_slice(&frame[0..6]);
    eth.src.copy_from_slice(&frame[6..12]);
    eth.et_be.copy_from_slice(&frame[12..14]);
    let et = be16(eth.et_be);
    let payload = &frame[ETH_HDR..];
    if !run_post(et, payload) {
        return Err("filtered post-recv");
    }
    match et {
        ET_ARP => {
            handle_arp(payload);
            Ok(())
        }
        ET_IPV4 => {
            if payload.len() < 20 {
                return Err("ipv4 too short");
            }
            // SAFETY: payload length checked, using read_unaligned for packed struct.
            let ip: Ipv4Header =
                unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const Ipv4Header) };
            if (ip.vihl >> 4) != 4 || (ip.vihl & 0x0F) != 5 {
                return Err("ipv4 header invalid");
            }
            if ip.proto == IP_PROTO_UDP {
                if payload.len() < 28 {
                    return Err("udp too short");
                }
                let udp_off = 20;
                // SAFETY: payload length checked, using read_unaligned for packed struct.
                let udp: UdpHeader = unsafe {
                    core::ptr::read_unaligned(payload.as_ptr().add(udp_off) as *const UdpHeader)
                };
                let dport = u16::from_be_bytes(udp.dport_be);
                let sport = u16::from_be_bytes(udp.sport_be);
                let ulen = u16::from_be_bytes(udp.len_be) as usize;
                if ulen < 8 || udp_off + ulen > payload.len() {
                    return Err("udp len invalid");
                }
                let data = &payload[udp_off + 8..udp_off + ulen];
                if let Some(h) = UDP_LISTENERS.lock().get(&dport).cloned() {
                    h(data, ip.src, sport);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn try_send_raw(frame: &[u8]) -> Result<(), &'static str> {
    if let Some(iface) = get_default_interface() {
        if !run_send(frame) {
            return Err("send filtered");
        }
        iface.send_packet(frame)
    } else {
        Err("no default interface")
    }
}
