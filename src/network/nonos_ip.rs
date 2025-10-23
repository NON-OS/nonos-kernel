//! Public IP types 

#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const IP_PROTOCOL_ICMP: u8 = 1;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub ttl: u8,
    pub protocol: u8,
    pub total_length: u16,
    pub header_length: u8,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub hop_limit: u8,
    pub next_header: u8,
    pub payload_length: u16,
}

#[derive(Debug, Clone)]
pub struct IpPacket<'a> {
    v4: Option<Ipv4Header>,
    v6: Option<Ipv6Header>,
    payload: &'a [u8],
}

impl<'a> IpPacket<'a> {
    pub fn parse_ipv4(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 { return Err("ipv4: too short"); }
        let ver_ihl = bytes[0];
        let ihl = ver_ihl & 0x0F;
        let header_len = (ihl * 4) as usize;
        if bytes.len() < header_len { return Err("ipv4: bad ihl"); }
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
                src, dst, ttl, protocol, total_length, header_length: ihl * 4
            }),
            v6: None,
            payload,
        })
    }

    pub fn dest_addr(&self) -> IpAddress {
        if let Some(h) = &self.v4 {
            IpAddress::V4(h.dst)
        } else {
            IpAddress::V6([0; 16])
        }
    }
    pub fn src_addr(&self) -> IpAddress {
        if let Some(h) = &self.v4 {
            IpAddress::V4(h.src)
        } else {
            IpAddress::V6([0; 16])
        }
    }
    pub fn protocol(&self) -> u8 {
        self.v4.as_ref().map(|h| h.protocol).unwrap_or(0)
    }
    pub fn payload(&self) -> &'a [u8] { self.payload }
    pub fn total_length(&self) -> u16 {
        self.v4.as_ref().map(|h| h.total_length).unwrap_or(0)
    }
    pub fn ttl(&self) -> u8 {
        self.v4.as_ref().map(|h| h.ttl).unwrap_or(0)
    }
}
