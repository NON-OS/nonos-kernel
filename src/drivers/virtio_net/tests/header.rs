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
use crate::test::framework::TestResult;

pub(crate) fn test_header_size_const() -> TestResult {
    if VirtioNetHeader::SIZE != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_header_size_of() -> TestResult {
    if core::mem::size_of::<VirtioNetHeader>() != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_header() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.flags != 0 {
        return TestResult::Fail;
    }
    if hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return TestResult::Fail;
    }
    if hdr.hdr_len != 0 {
        return TestResult::Fail;
    }
    if hdr.gso_size != 0 {
        return TestResult::Fail;
    }
    if hdr.csum_start != 0 {
        return TestResult::Fail;
    }
    if hdr.csum_offset != 0 {
        return TestResult::Fail;
    }
    if hdr.num_buffers != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_header() -> TestResult {
    let hdr = VirtioNetHeader::new();
    if hdr.flags != 0 {
        return TestResult::Fail;
    }
    if hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_simple_header() -> TestResult {
    let hdr = VirtioNetHeader::simple();
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    if hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_validates() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_no_gso() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.has_gso() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_no_csum() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.needs_csum() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_with_csum() -> TestResult {
    let hdr = VirtioNetHeader::with_csum(34, 6);
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    if !hdr.needs_csum() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_flags() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.flags = 0x80;
    if hdr.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_gso_type() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = 0x42;
    if hdr.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_tcpv4_invalid_without_params() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    if hdr.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_tcpv4_valid_with_params() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    hdr.hdr_len = 54;
    hdr.gso_size = 1460;
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_tcpv6() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    hdr.hdr_len = 74;
    hdr.gso_size = 1440;
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_udp() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
    hdr.hdr_len = 42;
    hdr.gso_size = 1472;
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_num_buffers_zero() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 0;
    if hdr.validate() != Err(VirtioNetError::InvalidHeader) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_num_buffers_too_large() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 257;
    if hdr.validate() != Err(VirtioNetError::InvalidHeader) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_valid_num_buffers() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.num_buffers = 128;
    if hdr.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_has_gso_none() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.has_gso() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_has_gso_tcpv4() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    if !hdr.has_gso() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_has_ecn() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    if hdr.has_ecn() {
        return TestResult::Fail;
    }

    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
    if !hdr.has_ecn() {
        return TestResult::Fail;
    }
    if !hdr.has_gso() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csum_valid_flag() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    if hdr.csum_valid() {
        return TestResult::Fail;
    }

    hdr.flags = VIRTIO_NET_HDR_F_DATA_VALID;
    if !hdr.csum_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_type_name_none() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.gso_type_name() != "none" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_type_name_tcpv4() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    if hdr.gso_type_name() != "tcpv4" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_type_name_tcpv6() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    if hdr.gso_type_name() != "tcpv6" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_type_name_udp() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
    if hdr.gso_type_name() != "udp" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gso_type_name_with_ecn() -> TestResult {
    let mut hdr = VirtioNetHeader::default();
    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
    if hdr.gso_type_name() != "tcpv4" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_bytes_length() -> TestResult {
    let hdr = VirtioNetHeader::default();
    if hdr.as_bytes().len() != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_csum_start_too_large() -> TestResult {
    let hdr = VirtioNetHeader::with_csum(2000, 0);
    if hdr.validate() != Err(VirtioNetError::InvalidHeader) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_invalid_csum_offset_too_large() -> TestResult {
    let hdr = VirtioNetHeader::with_csum(0, 2000);
    if hdr.validate() != Err(VirtioNetError::InvalidHeader) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_header_copy() -> TestResult {
    let hdr1 = VirtioNetHeader::with_csum(34, 6);
    let hdr2 = hdr1;
    if hdr1.csum_start != hdr2.csum_start {
        return TestResult::Fail;
    }
    if hdr1.csum_offset != hdr2.csum_offset {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_header_clone() -> TestResult {
    let hdr1 = VirtioNetHeader::simple();
    let hdr2 = hdr1.clone();
    if hdr1.flags != hdr2.flags {
        return TestResult::Fail;
    }
    if hdr1.gso_type != hdr2.gso_type {
        return TestResult::Fail;
    }
    TestResult::Pass
}
