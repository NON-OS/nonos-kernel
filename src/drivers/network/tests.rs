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

use super::error::NetworkError;

#[test]
fn test_network_error_display() {
    let err = NetworkError::NoInterface;
    assert_eq!(err.as_str(), "No network interface available");
}

#[test]
fn test_network_error_recoverable() {
    assert!(NetworkError::TxQueueFull.is_recoverable());
    assert!(NetworkError::RxQueueEmpty.is_recoverable());
    assert!(NetworkError::ConnectionTimeout.is_recoverable());
    assert!(!NetworkError::NoInterface.is_recoverable());
    assert!(!NetworkError::InvalidAddress.is_recoverable());
}

#[test]
fn test_ipv4_address_format() {
    let addr = [192u8, 168, 1, 1];
    assert_eq!(addr[0], 192);
    assert_eq!(addr[1], 168);
    assert_eq!(addr[2], 1);
    assert_eq!(addr[3], 1);
}

#[test]
fn test_mac_address_format() {
    let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(mac.len(), 6);
    assert_eq!(mac[0] & 0x01, 0);
    assert_eq!(mac[0] & 0x02, 0x02);
}

#[test]
fn test_ethernet_frame_size() {
    const ETH_HEADER_SIZE: usize = 14;
    const MIN_PAYLOAD: usize = 46;
    const MAX_PAYLOAD: usize = 1500;
    const FCS_SIZE: usize = 4;
    let min_frame = ETH_HEADER_SIZE + MIN_PAYLOAD + FCS_SIZE;
    let max_frame = ETH_HEADER_SIZE + MAX_PAYLOAD + FCS_SIZE;

    assert_eq!(min_frame, 64);
    assert_eq!(max_frame, 1518);
}
