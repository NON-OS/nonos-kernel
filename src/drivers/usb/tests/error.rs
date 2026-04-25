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

use crate::drivers::usb::error::UsbError;
use crate::test::framework::TestResult;

pub(crate) fn test_error_as_str_controller_not_found() -> TestResult {
    if UsbError::ControllerNotFound.as_str() != "USB controller not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_initialization_failed() -> TestResult {
    if UsbError::InitializationFailed.as_str() != "USB initialization failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_device_not_found() -> TestResult {
    if UsbError::DeviceNotFound.as_str() != "USB device not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_endpoint_not_found() -> TestResult {
    if UsbError::EndpointNotFound.as_str() != "Endpoint not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_transfer_failed() -> TestResult {
    if UsbError::TransferFailed.as_str() != "Transfer failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_transfer_timeout() -> TestResult {
    if UsbError::TransferTimeout.as_str() != "Transfer timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_transfer_stall() -> TestResult {
    if UsbError::TransferStall.as_str() != "Endpoint stalled" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_transfer_babble() -> TestResult {
    if UsbError::TransferBabble.as_str() != "Babble detected" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_buffer_overrun() -> TestResult {
    if UsbError::BufferOverrun.as_str() != "Buffer overrun" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_buffer_underrun() -> TestResult {
    if UsbError::BufferUnderrun.as_str() != "Buffer underrun" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_invalid_descriptor() -> TestResult {
    if UsbError::InvalidDescriptor.as_str() != "Invalid descriptor" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_invalid_configuration() -> TestResult {
    if UsbError::InvalidConfiguration.as_str() != "Invalid configuration" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_invalid_interface() -> TestResult {
    if UsbError::InvalidInterface.as_str() != "Invalid interface" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_invalid_endpoint() -> TestResult {
    if UsbError::InvalidEndpoint.as_str() != "Invalid endpoint" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_unsupported_device() -> TestResult {
    if UsbError::UnsupportedDevice.as_str() != "Unsupported device" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_unsupported_class() -> TestResult {
    if UsbError::UnsupportedClass.as_str() != "Unsupported device class" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_error() -> TestResult {
    if UsbError::PortError.as_str() != "Port error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_reset_failed() -> TestResult {
    if UsbError::ResetFailed.as_str() != "Device reset failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_enumeration_failed() -> TestResult {
    if UsbError::EnumerationFailed.as_str() != "Device enumeration failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_dma_error() -> TestResult {
    if UsbError::DmaError.as_str() != "DMA error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_command_ring_full() -> TestResult {
    if UsbError::CommandRingFull.as_str() != "Command ring full" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_event_ring_empty() -> TestResult {
    if UsbError::EventRingEmpty.as_str() != "Event ring empty" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_slot_not_enabled() -> TestResult {
    if UsbError::SlotNotEnabled.as_str() != "Slot not enabled" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_context_error() -> TestResult {
    if UsbError::ContextError.as_str() != "Context error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_timeout() -> TestResult {
    if !UsbError::TransferTimeout.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_stall() -> TestResult {
    if !UsbError::TransferStall.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_command_ring_full() -> TestResult {
    if !UsbError::CommandRingFull.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_event_ring_empty() -> TestResult {
    if !UsbError::EventRingEmpty.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_not_recoverable_controller_not_found() -> TestResult {
    if UsbError::ControllerNotFound.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_not_recoverable_device_not_found() -> TestResult {
    if UsbError::DeviceNotFound.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_not_recoverable_initialization_failed() -> TestResult {
    if UsbError::InitializationFailed.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_not_recoverable_dma_error() -> TestResult {
    if UsbError::DmaError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if UsbError::TransferTimeout != UsbError::TransferTimeout {
        return TestResult::Fail;
    }
    if UsbError::TransferTimeout == UsbError::TransferStall {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err1 = UsbError::TransferFailed;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err1 = UsbError::DeviceNotFound;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug() -> TestResult {
    use core::fmt::Write;
    let err = UsbError::TransferTimeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", err);
    if writer.as_str() != "TransferTimeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display() -> TestResult {
    use core::fmt::Write;
    let err = UsbError::TransferTimeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    if writer.as_str() != "Transfer timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_variants_have_message() -> TestResult {
    let errors = [
        UsbError::ControllerNotFound,
        UsbError::InitializationFailed,
        UsbError::DeviceNotFound,
        UsbError::EndpointNotFound,
        UsbError::TransferFailed,
        UsbError::TransferTimeout,
        UsbError::TransferStall,
        UsbError::TransferBabble,
        UsbError::BufferOverrun,
        UsbError::BufferUnderrun,
        UsbError::InvalidDescriptor,
        UsbError::InvalidConfiguration,
        UsbError::InvalidInterface,
        UsbError::InvalidEndpoint,
        UsbError::UnsupportedDevice,
        UsbError::UnsupportedClass,
        UsbError::PortError,
        UsbError::ResetFailed,
        UsbError::EnumerationFailed,
        UsbError::DmaError,
        UsbError::CommandRingFull,
        UsbError::EventRingEmpty,
        UsbError::SlotNotEnabled,
        UsbError::ContextError,
    ];

    for err in &errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_error_variant_count() -> TestResult {
    let errors = [
        UsbError::ControllerNotFound,
        UsbError::InitializationFailed,
        UsbError::DeviceNotFound,
        UsbError::EndpointNotFound,
        UsbError::TransferFailed,
        UsbError::TransferTimeout,
        UsbError::TransferStall,
        UsbError::TransferBabble,
        UsbError::BufferOverrun,
        UsbError::BufferUnderrun,
        UsbError::InvalidDescriptor,
        UsbError::InvalidConfiguration,
        UsbError::InvalidInterface,
        UsbError::InvalidEndpoint,
        UsbError::UnsupportedDevice,
        UsbError::UnsupportedClass,
        UsbError::PortError,
        UsbError::ResetFailed,
        UsbError::EnumerationFailed,
        UsbError::DmaError,
        UsbError::CommandRingFull,
        UsbError::EventRingEmpty,
        UsbError::SlotNotEnabled,
        UsbError::ContextError,
    ];

    if errors.len() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
