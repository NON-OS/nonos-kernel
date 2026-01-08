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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl Default for VirtioNetHeader {
    fn default() -> Self {
        Self {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }
}

impl VirtioNetHeader {
    pub const SIZE: usize = 12;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn simple() -> Self {
        Self {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }

    pub fn with_csum(csum_start: u16, csum_offset: u16) -> Self {
        Self {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start,
            csum_offset,
            num_buffers: 1,
        }
    }

    pub fn validate(&self) -> Result<(), VirtioNetError> {
        if self.flags & !VIRTIO_NET_HDR_F_ALL_VALID != 0 {
            return Err(VirtioNetError::InvalidHeader);
        }

        let gso_type = self.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
        match gso_type {
            VIRTIO_NET_HDR_GSO_NONE
            | VIRTIO_NET_HDR_GSO_TCPV4
            | VIRTIO_NET_HDR_GSO_UDP
            | VIRTIO_NET_HDR_GSO_TCPV6 => {}
            _ => return Err(VirtioNetError::InvalidHeader),
        }

        if gso_type != VIRTIO_NET_HDR_GSO_NONE {
            if self.hdr_len == 0 || self.hdr_len as usize > MAX_ETHERNET_FRAME {
                return Err(VirtioNetError::InvalidHeader);
            }

            if self.gso_size == 0 || self.gso_size as usize > MAX_MTU {
                return Err(VirtioNetError::InvalidHeader);
            }

            if self.hdr_len > self.gso_size + ETHERNET_HEADER_SIZE as u16 + 60 {
                return Err(VirtioNetError::InvalidHeader);
            }
        }

        if self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            if self.csum_start as usize >= MAX_ETHERNET_FRAME {
                return Err(VirtioNetError::InvalidHeader);
            }

            if self.csum_offset as usize >= MAX_ETHERNET_FRAME {
                return Err(VirtioNetError::InvalidHeader);
            }

            let csum_end = (self.csum_start as usize)
                .saturating_add(self.csum_offset as usize)
                .saturating_add(2);

            if csum_end > MAX_ETHERNET_FRAME {
                return Err(VirtioNetError::InvalidHeader);
            }
        }

        if self.num_buffers == 0 || self.num_buffers > 256 {
            return Err(VirtioNetError::InvalidHeader);
        }

        Ok(())
    }

    pub fn has_gso(&self) -> bool {
        (self.gso_type & !VIRTIO_NET_HDR_GSO_ECN) != VIRTIO_NET_HDR_GSO_NONE
    }

    pub fn has_ecn(&self) -> bool {
        (self.gso_type & VIRTIO_NET_HDR_GSO_ECN) != 0
    }

    pub fn needs_csum(&self) -> bool {
        (self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0
    }

    pub fn csum_valid(&self) -> bool {
        (self.flags & VIRTIO_NET_HDR_F_DATA_VALID) != 0
    }

    pub fn gso_type_name(&self) -> &'static str {
        match self.gso_type & !VIRTIO_NET_HDR_GSO_ECN {
            VIRTIO_NET_HDR_GSO_NONE => "none",
            VIRTIO_NET_HDR_GSO_TCPV4 => "tcpv4",
            VIRTIO_NET_HDR_GSO_UDP => "udp",
            VIRTIO_NET_HDR_GSO_TCPV6 => "tcpv6",
            _ => "unknown",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: self is a valid VirtioNetHeader with repr(C) layout
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(VirtioNetHeader::SIZE, 12);
        assert_eq!(core::mem::size_of::<VirtioNetHeader>(), 12);
    }

    #[test]
    fn test_default_header_valid() {
        let hdr = VirtioNetHeader::default();
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn test_simple_header_valid() {
        let hdr = VirtioNetHeader::simple();
        assert!(hdr.validate().is_ok());
        assert!(!hdr.has_gso());
        assert!(!hdr.needs_csum());
    }

    #[test]
    fn test_invalid_flags() {
        let mut hdr = VirtioNetHeader::default();
        hdr.flags = 0x80;
        assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
    }

    #[test]
    fn test_invalid_gso_type() {
        let mut hdr = VirtioNetHeader::default();
        hdr.gso_type = 0x42;
        assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));
    }

    #[test]
    fn test_gso_validation() {
        let mut hdr = VirtioNetHeader::default();
        hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
        assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));

        hdr.hdr_len = 54;
        hdr.gso_size = 1460;
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn test_csum_validation() {
        let hdr = VirtioNetHeader::with_csum(34, 6);
        assert!(hdr.validate().is_ok());
        assert!(hdr.needs_csum());

        let bad_hdr = VirtioNetHeader::with_csum(2000, 0);
        assert_eq!(bad_hdr.validate(), Err(VirtioNetError::InvalidHeader));
    }

    #[test]
    fn test_num_buffers_validation() {
        let mut hdr = VirtioNetHeader::default();
        hdr.num_buffers = 0;
        assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));

        hdr.num_buffers = 257;
        assert_eq!(hdr.validate(), Err(VirtioNetError::InvalidHeader));

        hdr.num_buffers = 128;
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn test_ecn_detection() {
        let mut hdr = VirtioNetHeader::default();
        assert!(!hdr.has_ecn());

        hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
        assert!(hdr.has_ecn());
        assert!(hdr.has_gso());
    }
}
