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
use crate::test::framework::TestResult;

pub(crate) fn test_packet_size_valid_min() -> TestResult {
    if validate_packet_size(60, false).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_packet_size_valid_max() -> TestResult {
    if validate_packet_size(1514, false).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_packet_size_valid_typical() -> TestResult {
    if validate_packet_size(64, false).is_err() {
        return TestResult::Fail;
    }
    if validate_packet_size(1000, false).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_packet_size_too_small() -> TestResult {
    if validate_packet_size(40, false) != Err(VirtioNetError::PacketTooSmall) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_packet_size_too_large() -> TestResult {
    if validate_packet_size(2000, false) != Err(VirtioNetError::PacketExceedsMtu) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_index_valid_zero() -> TestResult {
    if validate_descriptor_index(0, 256).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_index_valid_max() -> TestResult {
    if validate_descriptor_index(255, 256).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_index_invalid() -> TestResult {
    if validate_descriptor_index(256, 256) != Err(VirtioNetError::DescriptorOutOfBounds) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_index_overflow() -> TestResult {
    if validate_descriptor_index(1000, 256) != Err(VirtioNetError::DescriptorOutOfBounds) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chain_length_valid() -> TestResult {
    if validate_chain_length(&[0, 1, 2]).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chain_length_empty() -> TestResult {
    if validate_chain_length(&[]) != Err(VirtioNetError::QueueError) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chain_length_too_long() -> TestResult {
    let long_chain: alloc::vec::Vec<u16> = (0..20).collect();
    if validate_chain_length(&long_chain) != Err(VirtioNetError::DescriptorChainTooLong) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chain_length_max_valid() -> TestResult {
    let chain: alloc::vec::Vec<u16> = (0..16).collect();
    if validate_chain_length(&chain).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac_valid() -> TestResult {
    if validate_mac_address(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac_all_zeros() -> TestResult {
    if validate_mac_address(&[0x00; 6]) != Err(VirtioNetError::InvalidMacAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac_all_ones() -> TestResult {
    if validate_mac_address(&[0xFF; 6]) != Err(VirtioNetError::InvalidMacAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_source_mac_valid() -> TestResult {
    if validate_source_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_source_mac_multicast() -> TestResult {
    if validate_source_mac(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        != Err(VirtioNetError::InvalidMacAddress)
    {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethernet_frame_valid() -> TestResult {
    let frame =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    if validate_ethernet_frame(&frame).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethernet_frame_too_short() -> TestResult {
    if validate_ethernet_frame(&[0; 10]) != Err(VirtioNetError::MalformedPacket) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_ipv4() -> TestResult {
    let ipv4_frame =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    if validate_ethernet_frame_extended(&ipv4_frame) != Ok(EtherType::Ipv4) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_arp() -> TestResult {
    let arp_frame =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06];
    if validate_ethernet_frame_extended(&arp_frame) != Ok(EtherType::Arp) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_ipv6() -> TestResult {
    let ipv6_frame =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xDD];
    if validate_ethernet_frame_extended(&ipv6_frame) != Ok(EtherType::Ipv6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_other() -> TestResult {
    let other_frame =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0xB5];
    if validate_ethernet_frame_extended(&other_frame) != Ok(EtherType::Other(0x88B5)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_equality() -> TestResult {
    if EtherType::Ipv4 != EtherType::Ipv4 {
        return TestResult::Fail;
    }
    if EtherType::Ipv4 == EtherType::Ipv6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_other_values() -> TestResult {
    if EtherType::Other(0x1234) != EtherType::Other(0x1234) {
        return TestResult::Fail;
    }
    if EtherType::Other(0x1234) == EtherType::Other(0x5678) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
