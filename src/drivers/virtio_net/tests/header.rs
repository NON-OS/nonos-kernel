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

use crate::drivers::virtio_net::constants::*;
use crate::drivers::virtio_net::error::VirtioNetError;
use crate::drivers::virtio_net::header::VirtioNetHeader;

#[test]
fn test_header_size_const() {
    assert_eq!(VirtioNetHeader::SIZE, 12);
}

#[test]
fn test_header_size_of() {
    assert_eq!(core::mem::size_of::<VirtioNetHeader>(), 12);
}

#[test]
fn test_default_header() {
    let hdr = VirtioNetHeader::default();
    assert_eq!(hdr.flags, 0);
    assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
    assert_eq!(hdr.hdr_len, 0);
    assert_eq!(hdr.gso_size, 0);
    assert_eq!(hdr.csum_start, 0);
    assert_eq!(hdr.csum_offset, 0);
    assert_eq!(hdr.num_buffers, 1);
}

#[test]
fn test_new_header() {
    let hdr = VirtioNetHeader::new();
    assert_eq!(hdr.flags, 0);
    assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
}

#[test]
fn test_simple_header() {
    let hdr = VirtioNetHeader::simple();
    assert!(hdr.validate().is_ok());
    assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
}

#[test]
fn test_default_validates() {
    let hdr = VirtioNetHeader::default();
    assert!(hdr.validate().is_ok());
}

#[test]
fn test_default_no_gso() {
    let hdr = VirtioNetHeader::default();
    assert!(!hdr.has_gso());
}

#[test]
fn test_default_no_csum() {
    let hdr = VirtioNetHeader::default();
    assert!(!hdr.needs_csum());
}

#[test]
fn test_with_csum() {
    let hdr = VirtioNetHeader::with_csum(34, 6);
    assert!(hdr.validate().is_ok());
    assert!(hdr.needs_csum());
}

#[test]
fn test_invalid_flags() {
    let mut hdr = VirtioNetHeader::default();
    hdr.flags = 0x80;
    assert!(hdr.validate().is_err());
}

#[test]
fn test_invalid_gso_type() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = 0x42;
    assert!(hdr.validate().is_err());
}

#[test]
fn test_gso_tcpv4_invalid_without_params() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    assert!(hdr.validate().is_err());
}

#[test]
fn test_gso_tcpv4_valid_with_params() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    hdr.hdr_len = 54;
    hdr.gso_size = 1460;
    assert!(hdr.validate().is_ok());
}

#[test]
fn test_gso_tcpv6() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    hdr.hdr_len = 74;
    hdr.gso_size = 1440;
    assert!(hdr.validate().is_ok());
}

#[test]
fn test_gso_udp() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
    hdr.hdr_len = 42;
    hdr.gso_size = 1472;
    assert!(hdr.validate().is_ok());
}

#[test]
fn test_invalid_num_buffers_zero() {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 0;
    assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
}

#[test]
fn test_invalid_num_buffers_too_large() {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 257;
    assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
}

#[test]
fn test_valid_num_buffers() {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 128;
    assert!(hdr.validate().is_ok());
}

#[test]
fn test_has_gso_none() {
    let hdr = VirtioNetHeader::default();
    assert!(!hdr.has_gso());
}

#[test]
fn test_has_gso_tcpv4() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    assert!(hdr.has_gso());
}

#[test]
fn test_has_ecn() {
    let mut hdr = VirtioNetHeader::default();
    assert!(!hdr.has_ecn());

    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
    assert!(hdr.has_ecn());
    assert!(hdr.has_gso());
}

#[test]
fn test_csum_valid_flag() {
    let mut hdr = VirtioNetHeader::default();
    assert!(!hdr.csum_valid());

    hdr.flags = VIRTIO_NET_HDR_F_DATA_VALID;
    assert!(hdr.csum_valid());
}

#[test]
fn test_gso_type_name_none() {
    let hdr = VirtioNetHeader::default();
    assert_eq!(hdr.gso_type_name(), "none");
}

#[test]
fn test_gso_type_name_tcpv4() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    assert_eq!(hdr.gso_type_name(), "tcpv4");
}

#[test]
fn test_gso_type_name_tcpv6() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    assert_eq!(hdr.gso_type_name(), "tcpv6");
}

#[test]
fn test_gso_type_name_udp() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
    assert_eq!(hdr.gso_type_name(), "udp");
}

#[test]
fn test_gso_type_name_with_ecn() {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
    assert_eq!(hdr.gso_type_name(), "tcpv4");
}

#[test]
fn test_as_bytes_length() {
    let hdr = VirtioNetHeader::default();
    assert_eq!(hdr.as_bytes().len(), 12);
}

#[test]
fn test_invalid_csum_start_too_large() {
    let hdr = VirtioNetHeader::with_csum(2000, 0);
    assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
}

#[test]
fn test_invalid_csum_offset_too_large() {
    let hdr = VirtioNetHeader::with_csum(0, 2000);
    assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
}

#[test]
fn test_header_copy() {
    let hdr1 = VirtioNetHeader::with_csum(34, 6);
    let hdr2 = hdr1;
    assert_eq!(hdr1.csum_start, hdr2.csum_start);
    assert_eq!(hdr1.csum_offset, hdr2.csum_offset);
}

#[test]
fn test_header_clone() {
    let hdr1 = VirtioNetHeader::simple();
    let hdr2 = hdr1.clone();
    assert_eq!(hdr1.flags, hdr2.flags);
    assert_eq!(hdr1.gso_type, hdr2.gso_type);
}
