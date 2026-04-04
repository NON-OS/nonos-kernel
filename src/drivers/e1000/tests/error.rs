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

use crate::drivers::e1000::error::E1000Error;

#[test]
fn test_error_device_not_found_str() {
    assert_eq!(E1000Error::DeviceNotFound.as_str(), "E1000 device not found");
}

#[test]
fn test_error_initialization_failed_str() {
    assert_eq!(E1000Error::InitializationFailed.as_str(), "E1000 initialization failed");
}

#[test]
fn test_error_invalid_bar_str() {
    assert_eq!(E1000Error::InvalidBar.as_str(), "Invalid BAR configuration");
}

#[test]
fn test_error_eeprom_timeout_str() {
    assert_eq!(E1000Error::EepromTimeout.as_str(), "EEPROM read timeout");
}

#[test]
fn test_error_eeprom_read_failed_str() {
    assert_eq!(E1000Error::EepromReadFailed.as_str(), "EEPROM read failed");
}

#[test]
fn test_error_link_down_str() {
    assert_eq!(E1000Error::LinkDown.as_str(), "Network link is down");
}

#[test]
fn test_error_tx_queue_full_str() {
    assert_eq!(E1000Error::TxQueueFull.as_str(), "Transmit queue full");
}

#[test]
fn test_error_tx_timeout_str() {
    assert_eq!(E1000Error::TxTimeout.as_str(), "Transmit timeout");
}

#[test]
fn test_error_rx_buffer_empty_str() {
    assert_eq!(E1000Error::RxBufferEmpty.as_str(), "Receive buffer empty");
}

#[test]
fn test_error_invalid_packet_size_str() {
    assert_eq!(E1000Error::InvalidPacketSize.as_str(), "Invalid packet size");
}

#[test]
fn test_error_dma_allocation_failed_str() {
    assert_eq!(E1000Error::DmaAllocationFailed.as_str(), "DMA buffer allocation failed");
}

#[test]
fn test_error_invalid_mtu_str() {
    assert_eq!(E1000Error::InvalidMtu.as_str(), "Invalid MTU value");
}

#[test]
fn test_error_phy_error_str() {
    assert_eq!(E1000Error::PhyError.as_str(), "PHY communication error");
}

#[test]
fn test_error_reset_failed_str() {
    assert_eq!(E1000Error::ResetFailed.as_str(), "Device reset failed");
}

#[test]
fn test_error_interrupt_error_str() {
    assert_eq!(E1000Error::InterruptError.as_str(), "Interrupt configuration error");
}

#[test]
fn test_error_tx_queue_full_recoverable() {
    assert!(E1000Error::TxQueueFull.is_recoverable());
}

#[test]
fn test_error_rx_buffer_empty_recoverable() {
    assert!(E1000Error::RxBufferEmpty.is_recoverable());
}

#[test]
fn test_error_link_down_recoverable() {
    assert!(E1000Error::LinkDown.is_recoverable());
}

#[test]
fn test_error_tx_timeout_recoverable() {
    assert!(E1000Error::TxTimeout.is_recoverable());
}

#[test]
fn test_error_device_not_found_not_recoverable() {
    assert!(!E1000Error::DeviceNotFound.is_recoverable());
}

#[test]
fn test_error_initialization_failed_not_recoverable() {
    assert!(!E1000Error::InitializationFailed.is_recoverable());
}

#[test]
fn test_error_invalid_bar_not_recoverable() {
    assert!(!E1000Error::InvalidBar.is_recoverable());
}

#[test]
fn test_error_eeprom_timeout_not_recoverable() {
    assert!(!E1000Error::EepromTimeout.is_recoverable());
}

#[test]
fn test_error_eeprom_read_failed_not_recoverable() {
    assert!(!E1000Error::EepromReadFailed.is_recoverable());
}

#[test]
fn test_error_dma_allocation_failed_not_recoverable() {
    assert!(!E1000Error::DmaAllocationFailed.is_recoverable());
}

#[test]
fn test_error_invalid_mtu_not_recoverable() {
    assert!(!E1000Error::InvalidMtu.is_recoverable());
}

#[test]
fn test_error_phy_error_not_recoverable() {
    assert!(!E1000Error::PhyError.is_recoverable());
}

#[test]
fn test_error_reset_failed_not_recoverable() {
    assert!(!E1000Error::ResetFailed.is_recoverable());
}

#[test]
fn test_error_interrupt_error_not_recoverable() {
    assert!(!E1000Error::InterruptError.is_recoverable());
}

#[test]
fn test_error_invalid_packet_size_not_recoverable() {
    assert!(!E1000Error::InvalidPacketSize.is_recoverable());
}

#[test]
fn test_error_equality() {
    assert_eq!(E1000Error::TxTimeout, E1000Error::TxTimeout);
    assert_ne!(E1000Error::TxTimeout, E1000Error::LinkDown);
}

#[test]
fn test_error_copy() {
    let err1 = E1000Error::PhyError;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = E1000Error::EepromTimeout;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = E1000Error::LinkDown;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "LinkDown");
}

#[test]
fn test_error_display() {
    let err = E1000Error::LinkDown;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "Network link is down");
}

#[test]
fn test_all_errors_have_message() {
    let errors = [
        E1000Error::DeviceNotFound,
        E1000Error::InitializationFailed,
        E1000Error::InvalidBar,
        E1000Error::EepromTimeout,
        E1000Error::EepromReadFailed,
        E1000Error::LinkDown,
        E1000Error::TxQueueFull,
        E1000Error::TxTimeout,
        E1000Error::RxBufferEmpty,
        E1000Error::InvalidPacketSize,
        E1000Error::DmaAllocationFailed,
        E1000Error::InvalidMtu,
        E1000Error::PhyError,
        E1000Error::ResetFailed,
        E1000Error::InterruptError,
    ];

    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}
