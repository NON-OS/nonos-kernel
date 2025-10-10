//! IP Protocol Implementation
//!
//! IPv4 and IPv6 packet processing

use alloc::vec::Vec;

/// IP Protocol constants (RFC 790)
pub const IP_PROTOCOL_TCP: u8 = 6; // Transmission Control Protocol
pub const IP_PROTOCOL_UDP: u8 = 17; // User Datagram Protocol
pub const IP_PROTOCOL_ICMP: u8 = 1; // Internet Control Message Protocol

/// IP packet
pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

/// IPv4 header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

/// IPv6 header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    pub version_class_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

/// IP address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

/// IPv4 packet
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

/// IPv6 packet
pub struct Ipv6Packet {
    pub header: Ipv6Header,
    pub payload: Vec<u8>,
}

impl IpPacket {
    /// Get payload from the packet
    pub fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(packet) => &packet.payload,
            IpPacket::V6(packet) => &packet.payload,
        }
    }

    /// Get source address
    pub fn src_addr(&self) -> IpAddress {
        match self {
            IpPacket::V4(packet) => IpAddress::V4(packet.header.src_addr),
            IpPacket::V6(packet) => IpAddress::V6(packet.header.src_addr),
        }
    }

    /// Get destination address
    pub fn dest_addr(&self) -> IpAddress {
        match self {
            IpPacket::V4(packet) => IpAddress::V4(packet.header.dst_addr),
            IpPacket::V6(packet) => IpAddress::V6(packet.header.dst_addr),
        }
    }

    /// Get TTL (Time To Live)
    pub fn ttl(&self) -> u8 {
        match self {
            IpPacket::V4(packet) => packet.header.ttl,
            IpPacket::V6(packet) => packet.header.hop_limit,
        }
    }

    /// Get total length
    pub fn total_length(&self) -> u16 {
        match self {
            IpPacket::V4(packet) => packet.header.total_length,
            IpPacket::V6(packet) => packet.header.payload_length + 40, // IPv6 header is 40 bytes
        }
    }

    /// Get header checksum (IPv4 only)
    pub fn header_checksum(&self) -> u16 {
        match self {
            IpPacket::V4(packet) => packet.header.checksum,
            IpPacket::V6(_) => 0, // IPv6 doesn't have header checksum
        }
    }

    /// Parse IPv4 packet from raw bytes
    pub fn parse_ipv4(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 20 {
            return Err("IPv4 packet too short");
        }

        let version_ihl = data[0];
        let version = (version_ihl >> 4) & 0x0F;
        if version != 4 {
            return Err("Not an IPv4 packet");
        }

        let header_length = ((version_ihl & 0x0F) * 4) as usize;
        if data.len() < header_length {
            return Err("IPv4 header truncated");
        }

        let header = Ipv4Header {
            version_ihl,
            tos: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            id: u16::from_be_bytes([data[4], data[5]]),
            flags_fragment: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_addr: [data[12], data[13], data[14], data[15]],
            dst_addr: [data[16], data[17], data[18], data[19]],
        };

        let payload =
            if data.len() > header_length { data[header_length..].to_vec() } else { Vec::new() };

        Ok(IpPacket::V4(Ipv4Packet { header, payload }))
    }

    /// Get protocol from the packet
    pub fn protocol(&self) -> u8 {
        match self {
            IpPacket::V4(packet) => packet.header.protocol,
            IpPacket::V6(packet) => packet.header.next_header,
        }
    }
}
