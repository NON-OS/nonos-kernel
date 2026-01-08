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

use super::*;
#[cfg(test)]
mod error_tests {
    use super::error::*;
    #[test]
    fn test_error_messages() {
        assert_eq!(VirtioNetError::PacketTooSmall.as_str(), "packet too small");
        assert_eq!(VirtioNetError::RateLimitExceeded.as_str(), "rate limit exceeded");
        assert_eq!(VirtioNetError::InvalidMacAddress.as_str(), "invalid MAC address");
    }

    #[test]
    fn test_error_classification() {
        assert!(VirtioNetError::RateLimitExceeded.is_security_relevant());
        assert!(VirtioNetError::MalformedPacket.is_security_relevant());
        assert!(!VirtioNetError::BufferTooSmall.is_security_relevant());

        assert!(VirtioNetError::PacketTooSmall.is_recoverable());
        assert!(!VirtioNetError::QueueError.is_recoverable());

        assert!(VirtioNetError::DescriptorOutOfBounds.is_fatal());
        assert!(!VirtioNetError::NoBuffersAvailable.is_fatal());
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(VirtioNetError::PacketTooSmall.category(), ErrorCategory::PacketSize);
        assert_eq!(VirtioNetError::InvalidHeader.category(), ErrorCategory::PacketFormat);
        assert_eq!(VirtioNetError::QueueError.category(), ErrorCategory::Descriptor);
        assert_eq!(VirtioNetError::InvalidDmaAddress.category(), ErrorCategory::Memory);
        assert_eq!(VirtioNetError::RateLimitExceeded.category(), ErrorCategory::Security);
    }
}

#[cfg(test)]
mod header_tests {
    use super::header::*;
    use super::constants::*;

    #[test]
    fn test_header_size() {
        assert_eq!(VirtioNetHeader::SIZE, 12);
        assert_eq!(core::mem::size_of::<VirtioNetHeader>(), 12);
    }

    #[test]
    fn test_default_header() {
        let hdr = VirtioNetHeader::default();
        assert!(hdr.validate().is_ok());
        assert!(!hdr.has_gso());
        assert!(!hdr.needs_csum());
    }

    #[test]
    fn test_simple_header() {
        let hdr = VirtioNetHeader::simple();
        assert!(hdr.validate().is_ok());
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
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
    fn test_gso_validation() {
        let mut hdr = VirtioNetHeader::default();
        hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
        assert!(hdr.validate().is_err());

        hdr.hdr_len = 54;
        hdr.gso_size = 1460;
        assert!(hdr.validate().is_ok());
    }

    #[test]
    fn test_csum_header() {
        let hdr = VirtioNetHeader::with_csum(34, 6);
        assert!(hdr.validate().is_ok());
        assert!(hdr.needs_csum());
    }
}

#[cfg(test)]
mod validation_tests {
    use super::validation::*;
    use super::error::VirtioNetError;

    #[test]
    fn test_packet_size_validation() {
        assert!(validate_packet_size(64, false).is_ok());
        assert!(validate_packet_size(1514, false).is_ok());

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
        assert_eq!(validate_chain_length(&[]), Err(VirtioNetError::QueueError));

        let long_chain: alloc::vec::Vec<u16> = (0..20).collect();
        assert_eq!(
            validate_chain_length(&long_chain),
            Err(VirtioNetError::DescriptorChainTooLong)
        );
    }

    #[test]
    fn test_mac_validation() {
        assert!(validate_mac_address(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok());

        assert_eq!(
            validate_mac_address(&[0x00; 6]),
            Err(VirtioNetError::InvalidMacAddress)
        );

        assert_eq!(
            validate_mac_address(&[0xFF; 6]),
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
    }

    #[test]
    fn test_ethertype_classification() {
        let ipv4_frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00,
        ];
        assert_eq!(validate_ethernet_frame_extended(&ipv4_frame), Ok(EtherType::Ipv4));

        let arp_frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x06,
        ];
        assert_eq!(validate_ethernet_frame_extended(&arp_frame), Ok(EtherType::Arp));
    }
}

#[cfg(test)]
mod rate_limiter_tests {
    use super::rate_limiter::*;
    use super::error::VirtioNetError;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(1000, 100);
        assert_eq!(limiter.get_max_pps(), 1000);
        assert_eq!(limiter.get_burst_limit(), 100);
        assert_eq!(limiter.get_violations(), 0);
    }

    #[test]
    fn test_burst_limit() {
        let limiter = RateLimiter::new(1000, 10);

        for _ in 0..10 {
            assert!(limiter.check_rate_limit(0).is_ok());
        }

        assert_eq!(limiter.check_rate_limit(0), Err(VirtioNetError::RateLimitExceeded));
    }

    #[test]
    fn test_violation_counting() {
        let limiter = RateLimiter::new(1000, 5);

        for _ in 0..5 {
            let _ = limiter.check_rate_limit(0);
        }

        for _ in 0..3 {
            let _ = limiter.check_rate_limit(0);
        }

        assert_eq!(limiter.get_violations(), 3);
    }
}

#[cfg(test)]
mod stats_tests {
    use super::stats::*;
    use super::error::VirtioNetError;
    use core::sync::atomic::Ordering;

    #[test]
    fn test_stats_creation() {
        let stats = NetworkStats::new();
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_rx_tx() {
        let stats = NetworkStats::new();

        stats.record_rx(100);
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.rx_bytes.load(Ordering::Relaxed), 100);

        stats.record_tx(200);
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tx_bytes.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_error_recording() {
        let stats = NetworkStats::new();

        stats.record_error(VirtioNetError::MalformedPacket);
        assert_eq!(stats.malformed_packets.load(Ordering::Relaxed), 1);

        stats.record_error(VirtioNetError::RateLimitExceeded);
        assert_eq!(stats.rate_limit_violations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_snapshot() {
        let stats = NetworkStats::new();
        stats.record_rx(100);
        stats.record_tx(200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_packets, 1);
        assert_eq!(snapshot.tx_packets, 1);
        assert_eq!(snapshot.total_packets(), 2);
    }
}

#[cfg(test)]
mod virtqueue_tests {
    use super::virtqueue::*;
    use super::constants::*;

    #[test]
    fn test_virtq_desc_size() {
        assert_eq!(VirtqDesc::SIZE, 16);
    }

    #[test]
    fn test_virtq_desc_flags() {
        let mut desc = VirtqDesc::new();
        assert!(!desc.has_next());
        assert!(!desc.is_write());

        desc.flags = VIRTQ_DESC_F_NEXT;
        assert!(desc.has_next());

        desc.flags = VIRTQ_DESC_F_WRITE;
        assert!(desc.is_write());
    }
}

#[cfg(test)]
mod constants_tests {
    use super::constants::*;

    #[test]
    fn test_frame_size_constants() {
        assert!(MAX_ETHERNET_FRAME > MIN_ETHERNET_FRAME);
        assert_eq!(MAX_ETHERNET_FRAME, MAX_MTU + 14);
    }

    #[test]
    fn test_rate_limit_constants() {
        assert!(RATE_LIMIT_BURST_RX <= RATE_LIMIT_RX_PPS);
        assert!(RATE_LIMIT_BURST_TX <= RATE_LIMIT_TX_PPS);
    }
}
