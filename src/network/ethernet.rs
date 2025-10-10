//! Ethernet Protocol Implementation
//!
//! High-performance Ethernet frame processing

use alloc::vec::Vec;

/// Ethernet Type constants (RFC 7042)
pub const ETHERTYPE_IP: u16 = 0x0800; // IPv4
pub const ETHERTYPE_IPV6: u16 = 0x86DD; // IPv6
pub const ETHERTYPE_ARP: u16 = 0x0806; // Address Resolution Protocol

/// Ethernet frame header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

/// MAC Address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn new(addr: [u8; 6]) -> Self {
        MacAddress(addr)
    }

    pub fn broadcast() -> Self {
        MacAddress([0xFF; 6])
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }
}

/// Ethernet frame types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
}

/// Ethernet frame
pub struct EthernetFrame {
    pub header: EthernetHeader,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Parse ethernet frame from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 14 {
            return Err("Ethernet frame too short");
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];

        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        let header = EthernetHeader { dst_mac, src_mac, ethertype };

        let payload = data[14..].to_vec();

        Ok(EthernetFrame { header, payload })
    }

    /// Get ethertype from the frame
    pub fn ethertype(&self) -> EtherType {
        match self.header.ethertype {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            _ => EtherType::Ipv4, // Default fallback
        }
    }
}
