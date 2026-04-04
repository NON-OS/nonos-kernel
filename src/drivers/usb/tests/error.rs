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

#[test]
fn test_error_as_str_controller_not_found() {
    assert_eq!(UsbError::ControllerNotFound.as_str(), "USB controller not found");
}

#[test]
fn test_error_as_str_initialization_failed() {
    assert_eq!(UsbError::InitializationFailed.as_str(), "USB initialization failed");
}

#[test]
fn test_error_as_str_device_not_found() {
    assert_eq!(UsbError::DeviceNotFound.as_str(), "USB device not found");
}

#[test]
fn test_error_as_str_endpoint_not_found() {
    assert_eq!(UsbError::EndpointNotFound.as_str(), "Endpoint not found");
}

#[test]
fn test_error_as_str_transfer_failed() {
    assert_eq!(UsbError::TransferFailed.as_str(), "Transfer failed");
}

#[test]
fn test_error_as_str_transfer_timeout() {
    assert_eq!(UsbError::TransferTimeout.as_str(), "Transfer timeout");
}

#[test]
fn test_error_as_str_transfer_stall() {
    assert_eq!(UsbError::TransferStall.as_str(), "Endpoint stalled");
}

#[test]
fn test_error_as_str_transfer_babble() {
    assert_eq!(UsbError::TransferBabble.as_str(), "Babble detected");
}

#[test]
fn test_error_as_str_buffer_overrun() {
    assert_eq!(UsbError::BufferOverrun.as_str(), "Buffer overrun");
}

#[test]
fn test_error_as_str_buffer_underrun() {
    assert_eq!(UsbError::BufferUnderrun.as_str(), "Buffer underrun");
}

#[test]
fn test_error_as_str_invalid_descriptor() {
    assert_eq!(UsbError::InvalidDescriptor.as_str(), "Invalid descriptor");
}

#[test]
fn test_error_as_str_invalid_configuration() {
    assert_eq!(UsbError::InvalidConfiguration.as_str(), "Invalid configuration");
}

#[test]
fn test_error_as_str_invalid_interface() {
    assert_eq!(UsbError::InvalidInterface.as_str(), "Invalid interface");
}

#[test]
fn test_error_as_str_invalid_endpoint() {
    assert_eq!(UsbError::InvalidEndpoint.as_str(), "Invalid endpoint");
}

#[test]
fn test_error_as_str_unsupported_device() {
    assert_eq!(UsbError::UnsupportedDevice.as_str(), "Unsupported device");
}

#[test]
fn test_error_as_str_unsupported_class() {
    assert_eq!(UsbError::UnsupportedClass.as_str(), "Unsupported device class");
}

#[test]
fn test_error_as_str_port_error() {
    assert_eq!(UsbError::PortError.as_str(), "Port error");
}

#[test]
fn test_error_as_str_reset_failed() {
    assert_eq!(UsbError::ResetFailed.as_str(), "Device reset failed");
}

#[test]
fn test_error_as_str_enumeration_failed() {
    assert_eq!(UsbError::EnumerationFailed.as_str(), "Device enumeration failed");
}

#[test]
fn test_error_as_str_dma_error() {
    assert_eq!(UsbError::DmaError.as_str(), "DMA error");
}

#[test]
fn test_error_as_str_command_ring_full() {
    assert_eq!(UsbError::CommandRingFull.as_str(), "Command ring full");
}

#[test]
fn test_error_as_str_event_ring_empty() {
    assert_eq!(UsbError::EventRingEmpty.as_str(), "Event ring empty");
}

#[test]
fn test_error_as_str_slot_not_enabled() {
    assert_eq!(UsbError::SlotNotEnabled.as_str(), "Slot not enabled");
}

#[test]
fn test_error_as_str_context_error() {
    assert_eq!(UsbError::ContextError.as_str(), "Context error");
}

#[test]
fn test_error_is_recoverable_timeout() {
    assert!(UsbError::TransferTimeout.is_recoverable());
}

#[test]
fn test_error_is_recoverable_stall() {
    assert!(UsbError::TransferStall.is_recoverable());
}

#[test]
fn test_error_is_recoverable_command_ring_full() {
    assert!(UsbError::CommandRingFull.is_recoverable());
}

#[test]
fn test_error_is_recoverable_event_ring_empty() {
    assert!(UsbError::EventRingEmpty.is_recoverable());
}

#[test]
fn test_error_is_not_recoverable_controller_not_found() {
    assert!(!UsbError::ControllerNotFound.is_recoverable());
}

#[test]
fn test_error_is_not_recoverable_device_not_found() {
    assert!(!UsbError::DeviceNotFound.is_recoverable());
}

#[test]
fn test_error_is_not_recoverable_initialization_failed() {
    assert!(!UsbError::InitializationFailed.is_recoverable());
}

#[test]
fn test_error_is_not_recoverable_dma_error() {
    assert!(!UsbError::DmaError.is_recoverable());
}

#[test]
fn test_error_equality() {
    assert_eq!(UsbError::TransferTimeout, UsbError::TransferTimeout);
    assert_ne!(UsbError::TransferTimeout, UsbError::TransferStall);
}

#[test]
fn test_error_copy() {
    let err1 = UsbError::TransferFailed;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = UsbError::DeviceNotFound;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = UsbError::TransferTimeout;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "TransferTimeout");
}

#[test]
fn test_error_display() {
    let err = UsbError::TransferTimeout;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "Transfer timeout");
}

#[test]
fn test_all_error_variants_have_message() {
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
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_error_variant_count() {
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

    assert_eq!(errors.len(), 24);
}
