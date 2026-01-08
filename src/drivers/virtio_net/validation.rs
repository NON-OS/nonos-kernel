// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
use super::error::VirtioNetError;
use super::header::VirtioNetHeader;
use core::mem;
use x86_64::PhysAddr;

pub fn validate_packet_size(size: usize, include_header: bool) -> Result<(), VirtioNetError> {
    let header_size = if include_header {
        mem::size_of::<VirtioNetHeader>()
    } else {
        0
    };

    if size < header_size {
        return Err(VirtioNetError::PacketTooSmall);
    }

    let payload_size = size - header_size;

    if payload_size < MIN_ETHERNET_FRAME {
        return Err(VirtioNetError::PacketTooSmall);
    }

    if payload_size > MAX_ETHERNET_FRAME {
        return Err(VirtioNetError::PacketExceedsMtu);
    }

    Ok(())
}

pub fn validate_descriptor_index(idx: u16, queue_size: u16) -> Result<(), VirtioNetError> {
    if idx >= queue_size {
        return Err(VirtioNetError::DescriptorOutOfBounds);
    }
    Ok(())
}

pub fn validate_chain_length(chain: &[u16]) -> Result<(), VirtioNetError> {
    if chain.is_empty() {
        return Err(VirtioNetError::QueueError);
    }
    if chain.len() > MAX_DESC_CHAIN_LEN {
        return Err(VirtioNetError::DescriptorChainTooLong);
    }
    Ok(())
}

pub fn validate_dma_address(addr: PhysAddr, size: usize) -> Result<(), VirtioNetError> {
    if addr.as_u64() == 0 {
        return Err(VirtioNetError::InvalidDmaAddress);
    }

    if addr.as_u64() % DMA_ALIGNMENT as u64 != 0 {
        return Err(VirtioNetError::InvalidDmaAddress);
    }

    if size == 0 {
        return Err(VirtioNetError::InvalidDmaAddress);
    }

    if size > MAX_DMA_REGION_SIZE {
        return Err(VirtioNetError::InvalidDmaAddress);
    }

    if addr.as_u64().checked_add(size as u64).is_none() {
        return Err(VirtioNetError::InvalidDmaAddress);
    }

    Ok(())
}

pub fn validate_mac_address(mac: &[u8; 6]) -> Result<(), VirtioNetError> {
    if mac.iter().all(|&b| b == 0) {
        return Err(VirtioNetError::InvalidMacAddress);
    }

    if mac.iter().all(|&b| b == 0xFF) {
        return Err(VirtioNetError::InvalidMacAddress);
    }

    Ok(())
}

pub fn validate_source_mac(mac: &[u8; 6]) -> Result<(), VirtioNetError> {
    validate_mac_address(mac)?;

    if mac[0] & 0x01 != 0 {
        return Err(VirtioNetError::InvalidMacAddress);
    }

    Ok(())
}

pub fn validate_ethernet_frame(frame: &[u8]) -> Result<(), VirtioNetError> {
    if frame.len() < ETHERNET_HEADER_SIZE {
        return Err(VirtioNetError::MalformedPacket);
    }

    let src_mac: [u8; 6] = [
        frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
    ];

    validate_source_mac(&src_mac)?;

    Ok(())
}

pub fn validate_ethernet_frame_extended(frame: &[u8]) -> Result<EtherType, VirtioNetError> {
    validate_ethernet_frame(frame)?;

    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);

    match ethertype {
        0x0800 => Ok(EtherType::Ipv4),
        0x0806 => Ok(EtherType::Arp),
        0x86DD => Ok(EtherType::Ipv6),
        0x8100 => Ok(EtherType::Vlan),
        0x88A8 => Ok(EtherType::QinQ),
        _ if ethertype >= 0x0600 => Ok(EtherType::Other(ethertype)),
        _ => Ok(EtherType::Llc(ethertype)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Vlan,
    QinQ,
    Other(u16),
    Llc(u16),
}

pub fn validate_rx_packet(data: &[u8], reported_len: u32) -> Result<(), VirtioNetError> {
    let header_size = mem::size_of::<VirtioNetHeader>();

    if reported_len as usize > data.len() {
        return Err(VirtioNetError::MalformedPacket);
    }

    let min_size = header_size + MIN_ETHERNET_FRAME;
    if (reported_len as usize) < min_size {
        return Err(VirtioNetError::PacketTooSmall);
    }

    let max_size = header_size + MAX_ETHERNET_FRAME;
    if (reported_len as usize) > max_size {
        return Err(VirtioNetError::PacketExceedsMtu);
    }

    if data.len() >= header_size {
        // SAFETY: data pointer is valid and aligned for VirtioNetHeader read
        let hdr = unsafe { &*(data.as_ptr() as *const VirtioNetHeader) };
        hdr.validate()?;

        let frame = &data[header_size..reported_len as usize];
        validate_ethernet_frame(frame)?;
    }

    Ok(())
}

pub fn validate_tx_buffer(
    payload: &[u8],
    dma_addr: PhysAddr,
    buffer_capacity: usize,
) -> Result<(), VirtioNetError> {
    validate_packet_size(payload.len(), false)?;
    validate_ethernet_frame(payload)?;

    let total_size = mem::size_of::<VirtioNetHeader>() + payload.len();

    if total_size > buffer_capacity {
        return Err(VirtioNetError::BufferTooSmall);
    }

    validate_dma_address(dma_addr, total_size)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_size_validation() {
        assert!(validate_packet_size(64, false).is_ok());
        assert!(validate_packet_size(1514, false).is_ok());
        assert!(validate_packet_size(1526, true).is_ok());

        assert_eq!(
            validate_packet_size(40, false),
            Err(VirtioNetError::PacketTooSmall)
        );

        assert_eq!(
            validate_packet_size(2000, false),
            Err(VirtioNetError::PacketExceedsMtu)
        );
    }

    #[test]
    fn test_descriptor_index_validation() {
        assert!(validate_descriptor_index(0, 256).is_ok());
        assert!(validate_descriptor_index(255, 256).is_ok());
        assert_eq!(
            validate_descriptor_index(256, 256),
            Err(VirtioNetError::DescriptorOutOfBounds)
        );
    }

    #[test]
    fn test_chain_length_validation() {
        assert!(validate_chain_length(&[0, 1, 2]).is_ok());
        assert_eq!(
            validate_chain_length(&[]),
            Err(VirtioNetError::QueueError)
        );

        let long_chain: Vec<u16> = (0..20).collect();
        assert_eq!(
            validate_chain_length(&long_chain),
            Err(VirtioNetError::DescriptorChainTooLong)
        );
    }

    #[test]
    fn test_mac_validation() {
        assert!(validate_mac_address(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok());

        assert_eq!(
            validate_mac_address(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(VirtioNetError::InvalidMacAddress)
        );

        assert_eq!(
            validate_mac_address(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(VirtioNetError::InvalidMacAddress)
        );
    }

    #[test]
    fn test_source_mac_validation() {
        assert!(validate_source_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok());

        assert_eq!(
            validate_source_mac(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(VirtioNetError::InvalidMacAddress)
        );
    }

    #[test]
    fn test_ethernet_frame_validation() {
        let frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00,
        ];
        assert!(validate_ethernet_frame(&frame).is_ok());

        assert_eq!(
            validate_ethernet_frame(&[0; 10]),
            Err(VirtioNetError::MalformedPacket)
        );

        let bad_frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00,
        ];
        assert_eq!(
            validate_ethernet_frame(&bad_frame),
            Err(VirtioNetError::InvalidMacAddress)
        );
    }

    #[test]
    fn test_ethertype_classification() {
        let ipv4_frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00,
        ];
        assert_eq!(
            validate_ethernet_frame_extended(&ipv4_frame),
            Ok(EtherType::Ipv4)
        );

        let arp_frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x06,
        ];
        assert_eq!(
            validate_ethernet_frame_extended(&arp_frame),
            Ok(EtherType::Arp)
        );
    }
}
