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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::core::get_network_stack;
use super::device::DEVICE_SLOT;
use super::types::SocketInfo;
use super::util::{build_ipv4_packet, ip_checksum, build_ethernet_frame};

static LINK_UP: AtomicBool = AtomicBool::new(false);

pub fn is_network_connected() -> bool {
    if !LINK_UP.load(Ordering::Relaxed) {
        return false;
    }
    if let Some((ip, _)) = get_current_ipv4() {
        ip != [0, 0, 0, 0] && ip != [127, 0, 0, 1]
    } else {
        false
    }
}

pub fn set_network_connected(link_up: bool) {
    LINK_UP.store(link_up, Ordering::Relaxed);
}

pub fn is_link_up() -> bool {
    LINK_UP.load(Ordering::Relaxed)
}

pub fn get_socket_info(socket_id: u32) -> Option<SocketInfo> {
    get_network_stack()
        .and_then(|stack| {
            stack.get_socket_info()
                .into_iter()
                .find(|s| s.id == socket_id)
        })
}

pub fn get_current_ipv4() -> Option<([u8; 4], u8)> {
    get_network_stack().and_then(|s| s.get_ipv4_config())
}

pub fn get_current_gateway() -> Option<[u8; 4]> {
    get_network_stack().and_then(|s| s.get_gateway_v4())
}

pub fn get_current_dns() -> [u8; 4] {
    get_network_stack().map(|s| s.get_default_dns_v4()).unwrap_or([1, 1, 1, 1])
}

pub fn get_mac_address() -> [u8; 6] {
    get_network_stack().map(|s| s.get_mac_address()).unwrap_or(super::device::DEFAULT_MAC)
}

pub fn is_network_available() -> bool {
    DEVICE_SLOT.get().is_some() && get_network_stack().is_some()
}

/// Build a raw IPv4 packet with the specified protocol and payload
pub fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    build_ipv4_packet(&src, &dst, protocol, payload)
}

/// Calculate the IP header checksum for a given IP header
pub fn calculate_ip_checksum(header: &[u8]) -> u16 {
    ip_checksum(header)
}

/// Build a raw Ethernet frame with the specified ethertype and payload
pub fn make_ethernet_frame(src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    build_ethernet_frame(&src_mac, &dst_mac, ethertype, payload)
}

pub fn send_ipv6_packet(packet: &[u8]) -> Result<(), i32> {
    if packet.len() < 40 { return Err(-22); }
    let stack = get_network_stack().ok_or(-19)?;
    let src_mac = stack.get_mac_address();
    let mut dst = [0u8; 16]; dst.copy_from_slice(&packet[24..40]);
    let dst_addr = crate::network::ipv6::Ipv6Address(dst);
    let dst_mac = if dst_addr.is_multicast() {
        [0x33, 0x33, dst[12], dst[13], dst[14], dst[15]]
    } else {
        crate::network::ipv6::neighbor::resolve_neighbor(&dst_addr).unwrap_or([0xff; 6])
    };
    let frame = build_ethernet_frame(&src_mac, &dst_mac, 0x86DD, packet);
    let dev = DEVICE_SLOT.get().ok_or(-19)?;
    dev.transmit(&frame).map_err(|_| -5)?;
    Ok(())
}

pub fn get_mac_address_opt() -> Option<[u8; 6]> {
    get_network_stack().map(|s| s.get_mac_address())
}
