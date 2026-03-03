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

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address};

use super::constants::{DHCP_MAGIC, dhcp_msg, dhcp_opt};
use super::types::DhcpLeaseInfo;
use crate::network::stack::device::now_ms;

pub(super) fn build_dhcp_message(
    mac: &[u8; 6],
    xid: u32,
    msg_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_ip: Option<[u8; 4]>,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 576];

    pkt[0] = 1;
    pkt[1] = 1;
    pkt[2] = 6;
    pkt[3] = 0;

    pkt[4..8].copy_from_slice(&xid.to_be_bytes());

    pkt[10] = 0x80;

    if msg_type == dhcp_msg::REQUEST && requested_ip.is_some() && server_ip.is_none() {
        if let Some(ip) = requested_ip {
            pkt[12..16].copy_from_slice(&ip);
        }
    }

    pkt[28..34].copy_from_slice(mac);

    pkt[236..240].copy_from_slice(&DHCP_MAGIC);

    let mut opt = 240;

    pkt[opt] = dhcp_opt::MSG_TYPE;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = msg_type;
    opt += 3;

    pkt[opt] = dhcp_opt::CLIENT_ID;
    pkt[opt + 1] = 7;
    pkt[opt + 2] = 1;
    pkt[opt + 3..opt + 9].copy_from_slice(mac);
    opt += 9;

    if let Some(ip) = requested_ip {
        if msg_type != dhcp_msg::RELEASE {
            pkt[opt] = dhcp_opt::REQUESTED_IP;
            pkt[opt + 1] = 4;
            pkt[opt + 2..opt + 6].copy_from_slice(&ip);
            opt += 6;
        }
    }

    if let Some(sip) = server_ip {
        pkt[opt] = dhcp_opt::SERVER_ID;
        pkt[opt + 1] = 4;
        pkt[opt + 2..opt + 6].copy_from_slice(&sip);
        opt += 6;
    }

    if msg_type == dhcp_msg::DISCOVER || msg_type == dhcp_msg::REQUEST {
        pkt[opt] = dhcp_opt::PARAM_REQUEST;
        pkt[opt + 1] = 8;
        pkt[opt + 2] = dhcp_opt::SUBNET_MASK;
        pkt[opt + 3] = dhcp_opt::ROUTER;
        pkt[opt + 4] = dhcp_opt::DNS;
        pkt[opt + 5] = dhcp_opt::DOMAIN_NAME;
        pkt[opt + 6] = dhcp_opt::BROADCAST;
        pkt[opt + 7] = dhcp_opt::LEASE_TIME;
        pkt[opt + 8] = dhcp_opt::RENEWAL_TIME;
        pkt[opt + 9] = dhcp_opt::REBIND_TIME;
        opt += 10;
    }

    let hostname = b"nonos";
    pkt[opt] = dhcp_opt::HOSTNAME;
    pkt[opt + 1] = hostname.len() as u8;
    pkt[opt + 2..opt + 2 + hostname.len()].copy_from_slice(hostname);
    opt += 2 + hostname.len();

    pkt[opt] = dhcp_opt::END;

    pkt.truncate(opt + 1);
    pkt
}

pub(super) fn send_dhcp_broadcast(socket: &mut udp::Socket, data: &[u8]) -> Result<(), &'static str> {
    let endpoint = smoltcp::wire::IpEndpoint::new(
        SmolIpAddress::Ipv4(SmolIpv4Address::new(255, 255, 255, 255)),
        67,
    );
    let metadata = smoltcp::socket::udp::UdpMetadata::from(endpoint);
    socket.send_slice(data, metadata).map_err(|_| "dhcp send failed")
}

pub(super) fn parse_dhcp_response(data: &[u8]) -> Option<(u8, DhcpLeaseInfo)> {
    if data.len() < 240 {
        return None;
    }
    if data[236..240] != DHCP_MAGIC {
        return None;
    }

    let mut lease = DhcpLeaseInfo::default();
    lease.acquired_at = now_ms();

    lease.ip.copy_from_slice(&data[16..20]);

    if data[20..24] != [0, 0, 0, 0] {
        lease.server_ip.copy_from_slice(&data[20..24]);
    }

    let mut msg_type = 0u8;

    let mut i = 240;
    while i < data.len() && data[i] != dhcp_opt::END {
        if data[i] == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= data.len() {
            break;
        }

        let opt_type = data[i];
        let opt_len = data[i + 1] as usize;
        i += 2;

        if i + opt_len > data.len() {
            break;
        }

        match opt_type {
            dhcp_opt::SUBNET_MASK if opt_len >= 4 => {
                lease.subnet_mask.copy_from_slice(&data[i..i + 4]);
            }
            dhcp_opt::ROUTER if opt_len >= 4 => {
                lease.gateway.copy_from_slice(&data[i..i + 4]);
            }
            dhcp_opt::DNS if opt_len >= 4 => {
                lease.dns_primary.copy_from_slice(&data[i..i + 4]);
                if opt_len >= 8 {
                    lease.dns_secondary.copy_from_slice(&data[i + 4..i + 8]);
                }
            }
            dhcp_opt::DOMAIN_NAME if opt_len > 0 => {
                lease.domain = String::from_utf8_lossy(&data[i..i + opt_len]).into_owned();
            }
            dhcp_opt::BROADCAST if opt_len >= 4 => {
                lease.broadcast.copy_from_slice(&data[i..i + 4]);
            }
            dhcp_opt::LEASE_TIME if opt_len == 4 => {
                lease.lease_time = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            }
            dhcp_opt::MSG_TYPE if opt_len >= 1 => {
                msg_type = data[i];
            }
            dhcp_opt::SERVER_ID if opt_len >= 4 => {
                lease.server_ip.copy_from_slice(&data[i..i + 4]);
            }
            dhcp_opt::RENEWAL_TIME if opt_len == 4 => {
                lease.t1_time = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            }
            dhcp_opt::REBIND_TIME if opt_len == 4 => {
                lease.t2_time = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            }
            _ => {}
        }
        i += opt_len;
    }

    if lease.gateway == [0, 0, 0, 0] {
        lease.gateway = [lease.ip[0], lease.ip[1], lease.ip[2], 1];
    }
    if lease.dns_primary == [0, 0, 0, 0] {
        lease.dns_primary = [1, 1, 1, 1];
    }
    if lease.t1_time == 0 {
        lease.t1_time = lease.lease_time / 2;
    }
    if lease.t2_time == 0 {
        lease.t2_time = (lease.lease_time * 7) / 8;
    }

    if msg_type == 0 {
        return None;
    }

    Some((msg_type, lease))
}

pub(super) fn count_subnet_bits(mask: [u8; 4]) -> u8 {
    let val = u32::from_be_bytes(mask);
    val.count_ones() as u8
}
