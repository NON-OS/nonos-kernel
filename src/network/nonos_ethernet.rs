//! Ethernet helpers used by packet processing paths.

#![no_std]

pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct EthernetFrame<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 14 { return Err("ethernet: too short"); }
        let mut dst = [0u8; 6]; dst.copy_from_slice(&bytes[0..6]);
        let mut src = [0u8; 6]; src.copy_from_slice(&bytes[6..12]);
        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        Ok(Self {
            header: EthernetHeader { dst, src, ethertype },
            payload: &bytes[14..],
        })
    }

    pub fn ethertype(&self) -> EtherType {
        match self.header.ethertype {
            ETHERTYPE_IP => EtherType::Ipv4,
            ETHERTYPE_IPV6 => EtherType::Ipv6,
            ETHERTYPE_ARP => EtherType::Arp,
            x => EtherType::Other(x),
        }
    }
}
