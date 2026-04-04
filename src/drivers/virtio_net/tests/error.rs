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

use crate::drivers::virtio_net::error::{ErrorCategory, VirtioNetError};

#[test]
fn test_error_invalid_packet_size() {
    assert_eq!(VirtioNetError::InvalidPacketSize.as_str(), "invalid packet size");
}

#[test]
fn test_error_packet_too_small() {
    assert_eq!(VirtioNetError::PacketTooSmall.as_str(), "packet too small");
}

#[test]
fn test_error_packet_exceeds_mtu() {
    assert_eq!(VirtioNetError::PacketExceedsMtu.as_str(), "packet exceeds MTU");
}

#[test]
fn test_error_invalid_header() {
    assert_eq!(VirtioNetError::InvalidHeader.as_str(), "invalid virtio net header");
}

#[test]
fn test_error_descriptor_out_of_bounds() {
    assert_eq!(VirtioNetError::DescriptorOutOfBounds.as_str(), "descriptor out of bounds");
}

#[test]
fn test_error_descriptor_chain_too_long() {
    assert_eq!(VirtioNetError::DescriptorChainTooLong.as_str(), "descriptor chain too long");
}

#[test]
fn test_error_invalid_dma_address() {
    assert_eq!(VirtioNetError::InvalidDmaAddress.as_str(), "invalid DMA address");
}

#[test]
fn test_error_rate_limit_exceeded() {
    assert_eq!(VirtioNetError::RateLimitExceeded.as_str(), "rate limit exceeded");
}

#[test]
fn test_error_no_buffers_available() {
    assert_eq!(VirtioNetError::NoBuffersAvailable.as_str(), "no buffers available");
}

#[test]
fn test_error_no_descriptors_available() {
    assert_eq!(VirtioNetError::NoDescriptorsAvailable.as_str(), "no descriptors available");
}

#[test]
fn test_error_queue_error() {
    assert_eq!(VirtioNetError::QueueError.as_str(), "queue error");
}

#[test]
fn test_error_invalid_mac_address() {
    assert_eq!(VirtioNetError::InvalidMacAddress.as_str(), "invalid MAC address");
}

#[test]
fn test_error_malformed_packet() {
    assert_eq!(VirtioNetError::MalformedPacket.as_str(), "malformed packet");
}

#[test]
fn test_error_checksum_error() {
    assert_eq!(VirtioNetError::ChecksumError.as_str(), "checksum error");
}

#[test]
fn test_error_device_not_ready() {
    assert_eq!(VirtioNetError::DeviceNotReady.as_str(), "device not ready");
}

#[test]
fn test_error_buffer_too_small() {
    assert_eq!(VirtioNetError::BufferTooSmall.as_str(), "buffer too small");
}

#[test]
fn test_error_initialization_failed() {
    assert_eq!(VirtioNetError::InitializationFailed.as_str(), "initialization failed");
}

#[test]
fn test_error_feature_negotiation_failed() {
    assert_eq!(VirtioNetError::FeatureNegotiationFailed.as_str(), "feature negotiation failed");
}

#[test]
fn test_error_msix_configuration_failed() {
    assert_eq!(VirtioNetError::MsixConfigurationFailed.as_str(), "MSI-X configuration failed");
}

#[test]
fn test_error_queue_setup_failed() {
    assert_eq!(VirtioNetError::QueueSetupFailed.as_str(), "queue setup failed");
}

#[test]
fn test_error_allocation_failed() {
    assert_eq!(VirtioNetError::AllocationFailed.as_str(), "memory allocation failed");
}

#[test]
fn test_error_generic_error() {
    assert_eq!(VirtioNetError::GenericError.as_str(), "generic error");
}

#[test]
fn test_is_security_relevant_rate_limit() {
    assert!(VirtioNetError::RateLimitExceeded.is_security_relevant());
}

#[test]
fn test_is_security_relevant_invalid_mac() {
    assert!(VirtioNetError::InvalidMacAddress.is_security_relevant());
}

#[test]
fn test_is_security_relevant_malformed_packet() {
    assert!(VirtioNetError::MalformedPacket.is_security_relevant());
}

#[test]
fn test_is_security_relevant_invalid_header() {
    assert!(VirtioNetError::InvalidHeader.is_security_relevant());
}

#[test]
fn test_is_security_relevant_descriptor_out_of_bounds() {
    assert!(VirtioNetError::DescriptorOutOfBounds.is_security_relevant());
}

#[test]
fn test_is_not_security_relevant_buffer_too_small() {
    assert!(!VirtioNetError::BufferTooSmall.is_security_relevant());
}

#[test]
fn test_is_recoverable_packet_too_small() {
    assert!(VirtioNetError::PacketTooSmall.is_recoverable());
}

#[test]
fn test_is_recoverable_no_buffers() {
    assert!(VirtioNetError::NoBuffersAvailable.is_recoverable());
}

#[test]
fn test_is_not_recoverable_queue_error() {
    assert!(!VirtioNetError::QueueError.is_recoverable());
}

#[test]
fn test_is_fatal_descriptor_out_of_bounds() {
    assert!(VirtioNetError::DescriptorOutOfBounds.is_fatal());
}

#[test]
fn test_is_fatal_queue_error() {
    assert!(VirtioNetError::QueueError.is_fatal());
}

#[test]
fn test_is_not_fatal_packet_too_small() {
    assert!(!VirtioNetError::PacketTooSmall.is_fatal());
}

#[test]
fn test_category_packet_size() {
    assert_eq!(VirtioNetError::PacketTooSmall.category(), ErrorCategory::PacketSize);
    assert_eq!(VirtioNetError::PacketExceedsMtu.category(), ErrorCategory::PacketSize);
}

#[test]
fn test_category_packet_format() {
    assert_eq!(VirtioNetError::InvalidHeader.category(), ErrorCategory::PacketFormat);
    assert_eq!(VirtioNetError::MalformedPacket.category(), ErrorCategory::PacketFormat);
}

#[test]
fn test_category_descriptor() {
    assert_eq!(VirtioNetError::QueueError.category(), ErrorCategory::Descriptor);
    assert_eq!(VirtioNetError::DescriptorOutOfBounds.category(), ErrorCategory::Descriptor);
}

#[test]
fn test_category_memory() {
    assert_eq!(VirtioNetError::InvalidDmaAddress.category(), ErrorCategory::Memory);
    assert_eq!(VirtioNetError::AllocationFailed.category(), ErrorCategory::Memory);
}

#[test]
fn test_category_security() {
    assert_eq!(VirtioNetError::RateLimitExceeded.category(), ErrorCategory::Security);
    assert_eq!(VirtioNetError::InvalidMacAddress.category(), ErrorCategory::Security);
}

#[test]
fn test_category_device() {
    assert_eq!(VirtioNetError::DeviceNotReady.category(), ErrorCategory::Device);
    assert_eq!(VirtioNetError::InitializationFailed.category(), ErrorCategory::Device);
}

#[test]
fn test_error_category_as_str() {
    assert_eq!(ErrorCategory::PacketSize.as_str(), "packet_size");
    assert_eq!(ErrorCategory::PacketFormat.as_str(), "packet_format");
    assert_eq!(ErrorCategory::Descriptor.as_str(), "descriptor");
    assert_eq!(ErrorCategory::Memory.as_str(), "memory");
    assert_eq!(ErrorCategory::Security.as_str(), "security");
    assert_eq!(ErrorCategory::Device.as_str(), "device");
    assert_eq!(ErrorCategory::Other.as_str(), "other");
}

#[test]
fn test_error_equality() {
    assert_eq!(VirtioNetError::PacketTooSmall, VirtioNetError::PacketTooSmall);
    assert_ne!(VirtioNetError::PacketTooSmall, VirtioNetError::PacketExceedsMtu);
}

#[test]
fn test_error_display() {
    let err = VirtioNetError::PacketTooSmall;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "packet too small");
}

#[test]
fn test_all_errors_have_message() {
    let errors = [
        VirtioNetError::InvalidPacketSize,
        VirtioNetError::PacketTooSmall,
        VirtioNetError::PacketExceedsMtu,
        VirtioNetError::InvalidHeader,
        VirtioNetError::DescriptorOutOfBounds,
        VirtioNetError::DescriptorChainTooLong,
        VirtioNetError::InvalidDmaAddress,
        VirtioNetError::RateLimitExceeded,
        VirtioNetError::NoBuffersAvailable,
        VirtioNetError::NoDescriptorsAvailable,
        VirtioNetError::QueueError,
        VirtioNetError::InvalidMacAddress,
        VirtioNetError::MalformedPacket,
        VirtioNetError::ChecksumError,
        VirtioNetError::DeviceNotReady,
        VirtioNetError::BufferTooSmall,
        VirtioNetError::InitializationFailed,
        VirtioNetError::FeatureNegotiationFailed,
        VirtioNetError::MsixConfigurationFailed,
        VirtioNetError::QueueSetupFailed,
        VirtioNetError::AllocationFailed,
        VirtioNetError::GenericError,
    ];

    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}
