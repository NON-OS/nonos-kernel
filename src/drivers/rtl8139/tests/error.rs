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

use crate::drivers::rtl8139::error::Rtl8139Error;

#[test]
fn test_error_device_not_found_str() {
    assert_eq!(Rtl8139Error::DeviceNotFound.as_str(), "RTL8139 device not found");
}

#[test]
fn test_error_initialization_failed_str() {
    assert_eq!(Rtl8139Error::InitializationFailed.as_str(), "RTL8139 initialization failed");
}

#[test]
fn test_error_invalid_bar_str() {
    assert_eq!(Rtl8139Error::InvalidBar.as_str(), "Invalid BAR configuration");
}

#[test]
fn test_error_reset_timeout_str() {
    assert_eq!(Rtl8139Error::ResetTimeout.as_str(), "Device reset timeout");
}

#[test]
fn test_error_tx_queue_full_str() {
    assert_eq!(Rtl8139Error::TxQueueFull.as_str(), "Transmit queue full");
}

#[test]
fn test_error_tx_timeout_str() {
    assert_eq!(Rtl8139Error::TxTimeout.as_str(), "Transmit timeout");
}

#[test]
fn test_error_rx_buffer_overflow_str() {
    assert_eq!(Rtl8139Error::RxBufferOverflow.as_str(), "Receive buffer overflow");
}

#[test]
fn test_error_invalid_packet_size_str() {
    assert_eq!(Rtl8139Error::InvalidPacketSize.as_str(), "Invalid packet size");
}

#[test]
fn test_error_dma_allocation_failed_str() {
    assert_eq!(Rtl8139Error::DmaAllocationFailed.as_str(), "DMA buffer allocation failed");
}

#[test]
fn test_error_link_down_str() {
    assert_eq!(Rtl8139Error::LinkDown.as_str(), "Network link is down");
}

#[test]
fn test_error_crc_error_str() {
    assert_eq!(Rtl8139Error::CrcError.as_str(), "CRC error in received packet");
}

#[test]
fn test_error_frame_alignment_error_str() {
    assert_eq!(Rtl8139Error::FrameAlignmentError.as_str(), "Frame alignment error");
}

#[test]
fn test_error_runt_packet_str() {
    assert_eq!(Rtl8139Error::RuntPacket.as_str(), "Runt packet received");
}

#[test]
fn test_error_long_packet_str() {
    assert_eq!(Rtl8139Error::LongPacket.as_str(), "Packet too long");
}

#[test]
fn test_error_fifo_error_str() {
    assert_eq!(Rtl8139Error::FifoError.as_str(), "FIFO error");
}

#[test]
fn test_error_tx_queue_full_recoverable() {
    assert!(Rtl8139Error::TxQueueFull.is_recoverable());
}

#[test]
fn test_error_rx_buffer_overflow_recoverable() {
    assert!(Rtl8139Error::RxBufferOverflow.is_recoverable());
}

#[test]
fn test_error_link_down_recoverable() {
    assert!(Rtl8139Error::LinkDown.is_recoverable());
}

#[test]
fn test_error_tx_timeout_recoverable() {
    assert!(Rtl8139Error::TxTimeout.is_recoverable());
}

#[test]
fn test_error_device_not_found_not_recoverable() {
    assert!(!Rtl8139Error::DeviceNotFound.is_recoverable());
}

#[test]
fn test_error_initialization_failed_not_recoverable() {
    assert!(!Rtl8139Error::InitializationFailed.is_recoverable());
}

#[test]
fn test_error_invalid_bar_not_recoverable() {
    assert!(!Rtl8139Error::InvalidBar.is_recoverable());
}

#[test]
fn test_error_reset_timeout_not_recoverable() {
    assert!(!Rtl8139Error::ResetTimeout.is_recoverable());
}

#[test]
fn test_error_dma_allocation_failed_not_recoverable() {
    assert!(!Rtl8139Error::DmaAllocationFailed.is_recoverable());
}

#[test]
fn test_error_crc_error_not_recoverable() {
    assert!(!Rtl8139Error::CrcError.is_recoverable());
}

#[test]
fn test_error_frame_alignment_error_not_recoverable() {
    assert!(!Rtl8139Error::FrameAlignmentError.is_recoverable());
}

#[test]
fn test_error_runt_packet_not_recoverable() {
    assert!(!Rtl8139Error::RuntPacket.is_recoverable());
}

#[test]
fn test_error_long_packet_not_recoverable() {
    assert!(!Rtl8139Error::LongPacket.is_recoverable());
}

#[test]
fn test_error_fifo_error_not_recoverable() {
    assert!(!Rtl8139Error::FifoError.is_recoverable());
}

#[test]
fn test_error_invalid_packet_size_not_recoverable() {
    assert!(!Rtl8139Error::InvalidPacketSize.is_recoverable());
}

#[test]
fn test_error_equality() {
    assert_eq!(Rtl8139Error::TxTimeout, Rtl8139Error::TxTimeout);
    assert_ne!(Rtl8139Error::TxTimeout, Rtl8139Error::LinkDown);
}

#[test]
fn test_error_copy() {
    let err1 = Rtl8139Error::CrcError;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = Rtl8139Error::FifoError;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = Rtl8139Error::LinkDown;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "LinkDown");
}

#[test]
fn test_error_display() {
    let err = Rtl8139Error::LinkDown;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "Network link is down");
}

#[test]
fn test_all_errors_have_message() {
    let errors = [
        Rtl8139Error::DeviceNotFound,
        Rtl8139Error::InitializationFailed,
        Rtl8139Error::InvalidBar,
        Rtl8139Error::ResetTimeout,
        Rtl8139Error::TxQueueFull,
        Rtl8139Error::TxTimeout,
        Rtl8139Error::RxBufferOverflow,
        Rtl8139Error::InvalidPacketSize,
        Rtl8139Error::DmaAllocationFailed,
        Rtl8139Error::LinkDown,
        Rtl8139Error::CrcError,
        Rtl8139Error::FrameAlignmentError,
        Rtl8139Error::RuntPacket,
        Rtl8139Error::LongPacket,
        Rtl8139Error::FifoError,
    ];

    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}
