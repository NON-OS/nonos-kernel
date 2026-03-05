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

//! IP packet parsing

use super::types::IpAddress;
use super::header::{Ipv4Header, Ipv6Header};

/// Parsed IP packet
#[derive(Debug, Clone)]
pub struct IpPacket<'a> {
    v4: Option<Ipv4Header>,
    v6: Option<Ipv6Header>,
    payload: &'a [u8],
}

impl<'a> IpPacket<'a> {
    /// Parse IPv4 packet from raw bytes
    pub fn parse_ipv4(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < Ipv4Header::MIN_SIZE {
            return Err("ipv4: packet too short");
        }

        let ver_ihl = bytes[0];
        let version = ver_ihl >> 4;
        if version != 4 {
            return Err("ipv4: invalid version");
        }

        let ihl = ver_ihl & 0x0F;
        let header_len = (ihl * 4) as usize;
        if bytes.len() < header_len {
            return Err("ipv4: bad header length");
        }

        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let ttl = bytes[8];
        let protocol = bytes[9];
        let src = [bytes[12], bytes[13], bytes[14], bytes[15]];
        let dst = [bytes[16], bytes[17], bytes[18], bytes[19]];

        let payload = if (total_length as usize) >= header_len && (total_length as usize) <= bytes.len() {
            &bytes[header_len..total_length as usize]
        } else {
            &bytes[header_len..]
        };

        Ok(Self {
            v4: Some(Ipv4Header {
                src,
                dst,
                ttl,
                protocol,
                total_length,
                header_length: ihl * 4,
            }),
            v6: None,
            payload,
        })
    }

    /// Parse IPv6 packet from raw bytes
    pub fn parse_ipv6(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < Ipv6Header::SIZE {
            return Err("ipv6: packet too short");
        }

        let version = bytes[0] >> 4;
        if version != 6 {
            return Err("ipv6: invalid version");
        }

        let payload_length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let next_header = bytes[6];
        let hop_limit = bytes[7];

        let mut src = [0u8; 16];
        src.copy_from_slice(&bytes[8..24]);

        let mut dst = [0u8; 16];
        dst.copy_from_slice(&bytes[24..40]);

        let payload_end = Ipv6Header::SIZE + payload_length as usize;
        let payload = if payload_end <= bytes.len() {
            &bytes[Ipv6Header::SIZE..payload_end]
        } else {
            &bytes[Ipv6Header::SIZE..]
        };

        Ok(Self {
            v4: None,
            v6: Some(Ipv6Header {
                src,
                dst,
                hop_limit,
                next_header,
                payload_length,
            }),
            payload,
        })
    }

    /// Get destination address
    pub fn dest_addr(&self) -> IpAddress {
        if let Some(h) = &self.v4 {
            IpAddress::V4(h.dst)
        } else if let Some(h) = &self.v6 {
            IpAddress::V6(h.dst)
        } else {
            IpAddress::V4([0; 4])
        }
    }

    /// Get source address
    pub fn src_addr(&self) -> IpAddress {
        if let Some(h) = &self.v4 {
            IpAddress::V4(h.src)
        } else if let Some(h) = &self.v6 {
            IpAddress::V6(h.src)
        } else {
            IpAddress::V4([0; 4])
        }
    }

    /// Get protocol number
    pub fn protocol(&self) -> u8 {
        self.v4
            .as_ref()
            .map(|h| h.protocol)
            .or_else(|| self.v6.as_ref().map(|h| h.next_header))
            .unwrap_or(0)
    }

    /// Get payload bytes
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Get total length
    pub fn total_length(&self) -> u16 {
        self.v4.as_ref().map(|h| h.total_length).unwrap_or(0)
    }

    /// Get TTL (IPv4) or hop limit (IPv6)
    pub fn ttl(&self) -> u8 {
        self.v4
            .as_ref()
            .map(|h| h.ttl)
            .or_else(|| self.v6.as_ref().map(|h| h.hop_limit))
            .unwrap_or(0)
    }

    /// Check if this is an IPv4 packet
    pub fn is_ipv4(&self) -> bool {
        self.v4.is_some()
    }

    /// Check if this is an IPv6 packet
    pub fn is_ipv6(&self) -> bool {
        self.v6.is_some()
    }
}
