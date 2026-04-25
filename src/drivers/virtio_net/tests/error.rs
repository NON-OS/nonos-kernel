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
use crate::test::framework::TestResult;

pub(crate) fn test_error_invalid_packet_size() -> TestResult {
    if VirtioNetError::InvalidPacketSize.as_str() != "invalid packet size" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_packet_too_small() -> TestResult {
    if VirtioNetError::PacketTooSmall.as_str() != "packet too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_packet_exceeds_mtu() -> TestResult {
    if VirtioNetError::PacketExceedsMtu.as_str() != "packet exceeds MTU" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_header() -> TestResult {
    if VirtioNetError::InvalidHeader.as_str() != "invalid virtio net header" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_descriptor_out_of_bounds() -> TestResult {
    if VirtioNetError::DescriptorOutOfBounds.as_str() != "descriptor out of bounds" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_descriptor_chain_too_long() -> TestResult {
    if VirtioNetError::DescriptorChainTooLong.as_str() != "descriptor chain too long" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_dma_address() -> TestResult {
    if VirtioNetError::InvalidDmaAddress.as_str() != "invalid DMA address" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_rate_limit_exceeded() -> TestResult {
    if VirtioNetError::RateLimitExceeded.as_str() != "rate limit exceeded" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_no_buffers_available() -> TestResult {
    if VirtioNetError::NoBuffersAvailable.as_str() != "no buffers available" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_no_descriptors_available() -> TestResult {
    if VirtioNetError::NoDescriptorsAvailable.as_str() != "no descriptors available" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_queue_error() -> TestResult {
    if VirtioNetError::QueueError.as_str() != "queue error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_mac_address() -> TestResult {
    if VirtioNetError::InvalidMacAddress.as_str() != "invalid MAC address" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_malformed_packet() -> TestResult {
    if VirtioNetError::MalformedPacket.as_str() != "malformed packet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_checksum_error() -> TestResult {
    if VirtioNetError::ChecksumError.as_str() != "checksum error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_device_not_ready() -> TestResult {
    if VirtioNetError::DeviceNotReady.as_str() != "device not ready" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small() -> TestResult {
    if VirtioNetError::BufferTooSmall.as_str() != "buffer too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_initialization_failed() -> TestResult {
    if VirtioNetError::InitializationFailed.as_str() != "initialization failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_feature_negotiation_failed() -> TestResult {
    if VirtioNetError::FeatureNegotiationFailed.as_str() != "feature negotiation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_msix_configuration_failed() -> TestResult {
    if VirtioNetError::MsixConfigurationFailed.as_str() != "MSI-X configuration failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_queue_setup_failed() -> TestResult {
    if VirtioNetError::QueueSetupFailed.as_str() != "queue setup failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_allocation_failed() -> TestResult {
    if VirtioNetError::AllocationFailed.as_str() != "memory allocation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_generic_error() -> TestResult {
    if VirtioNetError::GenericError.as_str() != "generic error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_security_relevant_rate_limit() -> TestResult {
    if !VirtioNetError::RateLimitExceeded.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_security_relevant_invalid_mac() -> TestResult {
    if !VirtioNetError::InvalidMacAddress.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_security_relevant_malformed_packet() -> TestResult {
    if !VirtioNetError::MalformedPacket.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_security_relevant_invalid_header() -> TestResult {
    if !VirtioNetError::InvalidHeader.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_security_relevant_descriptor_out_of_bounds() -> TestResult {
    if !VirtioNetError::DescriptorOutOfBounds.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_not_security_relevant_buffer_too_small() -> TestResult {
    if VirtioNetError::BufferTooSmall.is_security_relevant() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_recoverable_packet_too_small() -> TestResult {
    if !VirtioNetError::PacketTooSmall.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_recoverable_no_buffers() -> TestResult {
    if !VirtioNetError::NoBuffersAvailable.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_not_recoverable_queue_error() -> TestResult {
    if VirtioNetError::QueueError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_fatal_descriptor_out_of_bounds() -> TestResult {
    if !VirtioNetError::DescriptorOutOfBounds.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_fatal_queue_error() -> TestResult {
    if !VirtioNetError::QueueError.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_not_fatal_packet_too_small() -> TestResult {
    if VirtioNetError::PacketTooSmall.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_packet_size() -> TestResult {
    if VirtioNetError::PacketTooSmall.category() != ErrorCategory::PacketSize {
        return TestResult::Fail;
    }
    if VirtioNetError::PacketExceedsMtu.category() != ErrorCategory::PacketSize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_packet_format() -> TestResult {
    if VirtioNetError::InvalidHeader.category() != ErrorCategory::PacketFormat {
        return TestResult::Fail;
    }
    if VirtioNetError::MalformedPacket.category() != ErrorCategory::PacketFormat {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_descriptor() -> TestResult {
    if VirtioNetError::QueueError.category() != ErrorCategory::Descriptor {
        return TestResult::Fail;
    }
    if VirtioNetError::DescriptorOutOfBounds.category() != ErrorCategory::Descriptor {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_memory() -> TestResult {
    if VirtioNetError::InvalidDmaAddress.category() != ErrorCategory::Memory {
        return TestResult::Fail;
    }
    if VirtioNetError::AllocationFailed.category() != ErrorCategory::Memory {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_security() -> TestResult {
    if VirtioNetError::RateLimitExceeded.category() != ErrorCategory::Security {
        return TestResult::Fail;
    }
    if VirtioNetError::InvalidMacAddress.category() != ErrorCategory::Security {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_category_device() -> TestResult {
    if VirtioNetError::DeviceNotReady.category() != ErrorCategory::Device {
        return TestResult::Fail;
    }
    if VirtioNetError::InitializationFailed.category() != ErrorCategory::Device {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_category_as_str() -> TestResult {
    if ErrorCategory::PacketSize.as_str() != "packet_size" {
        return TestResult::Fail;
    }
    if ErrorCategory::PacketFormat.as_str() != "packet_format" {
        return TestResult::Fail;
    }
    if ErrorCategory::Descriptor.as_str() != "descriptor" {
        return TestResult::Fail;
    }
    if ErrorCategory::Memory.as_str() != "memory" {
        return TestResult::Fail;
    }
    if ErrorCategory::Security.as_str() != "security" {
        return TestResult::Fail;
    }
    if ErrorCategory::Device.as_str() != "device" {
        return TestResult::Fail;
    }
    if ErrorCategory::Other.as_str() != "other" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if VirtioNetError::PacketTooSmall != VirtioNetError::PacketTooSmall {
        return TestResult::Fail;
    }
    if VirtioNetError::PacketTooSmall == VirtioNetError::PacketExceedsMtu {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display() -> TestResult {
    use core::fmt::Write;
    let err = VirtioNetError::PacketTooSmall;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    if writer.as_str() != "packet too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_errors_have_message() -> TestResult {
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
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
