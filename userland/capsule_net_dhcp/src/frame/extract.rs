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

use super::ethernet::{self, ETHERTYPE_IPV4};
use super::ipv4::{self, PROTO_UDP};
use super::udp;
use crate::dhcp::{CLIENT_PORT, SERVER_PORT};

// Strip ethernet + ipv4 + udp headers and return the BOOTP body
// slice if the frame is a DHCP server reply addressed at the
// client port. Returns `None` for any unmatched frame.
pub fn dhcp_payload<'a>(frame: &'a [u8]) -> Option<&'a [u8]> {
    let (_dst, _src, ethertype) = ethernet::parse(frame)?;
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip_body = &frame[ethernet::HDR_LEN..];
    let (_ip_src, _ip_dst, proto, ip_hdr_len) = ipv4::parse(ip_body)?;
    if proto != PROTO_UDP {
        return None;
    }
    let udp_body = &ip_body[ip_hdr_len..];
    let (src_port, dst_port, udp_seg_len) = udp::parse(udp_body)?;
    if src_port != SERVER_PORT || dst_port != CLIENT_PORT {
        return None;
    }
    Some(&udp_body[udp::HDR_LEN..udp_seg_len])
}
