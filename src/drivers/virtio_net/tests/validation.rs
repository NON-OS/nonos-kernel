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

use crate::drivers::virtio_net::error::VirtioNetError;
use crate::drivers::virtio_net::validation::*;

#[test]
fn test_packet_size_valid_min() {
    assert!(validate_packet_size(60, false).is_ok());
}

#[test]
fn test_packet_size_valid_max() {
    assert!(validate_packet_size(1514, false).is_ok());
}

#[test]
fn test_packet_size_valid_typical() {
    assert!(validate_packet_size(64, false).is_ok());
    assert!(validate_packet_size(1000, false).is_ok());
}

#[test]
fn test_packet_size_too_small() {
    assert_eq!(
        validate_packet_size(40, false),
        Err(VirtioNetError::PacketTooSmall)
    );
}

#[test]
fn test_packet_size_too_large() {
    assert_eq!(
        validate_packet_size(2000, false),
        Err(VirtioNetError::PacketExceedsMtu)
    );
}

#[test]
fn test_descriptor_index_valid_zero() {
    assert!(validate_descriptor_index(0, 256).is_ok());
}

#[test]
fn test_descriptor_index_valid_max() {
    assert!(validate_descriptor_index(255, 256).is_ok());
}

#[test]
fn test_descriptor_index_invalid() {
    assert_eq!(
        validate_descriptor_index(256, 256),
        Err(VirtioNetError::DescriptorOutOfBounds)
    );
}

#[test]
fn test_descriptor_index_overflow() {
    assert_eq!(
        validate_descriptor_index(1000, 256),
        Err(VirtioNetError::DescriptorOutOfBounds)
    );
}

#[test]
fn test_chain_length_valid() {
    assert!(validate_chain_length(&[0, 1, 2]).is_ok());
}

#[test]
fn test_chain_length_empty() {
    assert_eq!(validate_chain_length(&[]), Err(VirtioNetError::QueueError));
}

#[test]
fn test_chain_length_too_long() {
    let long_chain: alloc::vec::Vec<u16> = (0..20).collect();
    assert_eq!(
        validate_chain_length(&long_chain),
        Err(VirtioNetError::DescriptorChainTooLong)
    );
}

#[test]
fn test_chain_length_max_valid() {
    let chain: alloc::vec::Vec<u16> = (0..16).collect();
    assert!(validate_chain_length(&chain).is_ok());
}

#[test]
fn test_mac_valid() {
    assert!(validate_mac_address(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok());
}

#[test]
fn test_mac_all_zeros() {
    assert_eq!(
        validate_mac_address(&[0x00; 6]),
        Err(VirtioNetError::InvalidMacAddress)
    );
}

#[test]
fn test_mac_all_ones() {
    assert_eq!(
        validate_mac_address(&[0xFF; 6]),
        Err(VirtioNetError::InvalidMacAddress)
    );
}

#[test]
fn test_source_mac_valid() {
    assert!(validate_source_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok());
}

#[test]
fn test_source_mac_multicast() {
    assert_eq!(
        validate_source_mac(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Err(VirtioNetError::InvalidMacAddress)
    );
}

#[test]
fn test_ethernet_frame_valid() {
    let frame = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
    ];
    assert!(validate_ethernet_frame(&frame).is_ok());
}

#[test]
fn test_ethernet_frame_too_short() {
    assert_eq!(
        validate_ethernet_frame(&[0; 10]),
        Err(VirtioNetError::MalformedPacket)
    );
}

#[test]
fn test_ethertype_ipv4() {
    let ipv4_frame = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
    ];
    assert_eq!(validate_ethernet_frame_extended(&ipv4_frame), Ok(EtherType::Ipv4));
}

#[test]
fn test_ethertype_arp() {
    let arp_frame = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06,
    ];
    assert_eq!(validate_ethernet_frame_extended(&arp_frame), Ok(EtherType::Arp));
}

#[test]
fn test_ethertype_ipv6() {
    let ipv6_frame = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x86, 0xDD,
    ];
    assert_eq!(validate_ethernet_frame_extended(&ipv6_frame), Ok(EtherType::Ipv6));
}

#[test]
fn test_ethertype_other() {
    let other_frame = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x88, 0xB5,
    ];
    assert_eq!(validate_ethernet_frame_extended(&other_frame), Ok(EtherType::Other(0x88B5)));
}

#[test]
fn test_ethertype_equality() {
    assert_eq!(EtherType::Ipv4, EtherType::Ipv4);
    assert_ne!(EtherType::Ipv4, EtherType::Ipv6);
}

#[test]
fn test_ethertype_other_values() {
    assert_eq!(EtherType::Other(0x1234), EtherType::Other(0x1234));
    assert_ne!(EtherType::Other(0x1234), EtherType::Other(0x5678));
}
