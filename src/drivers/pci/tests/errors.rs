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

use crate::drivers::pci::*;

#[test]
fn test_error_display() {
    let err = error::PciError::InvalidDevice(32);
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("32"));

    let err = error::PciError::DeviceBlocked { vendor: 0x1234, device: 0x5678 };
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("1234"));
    assert!(msg.contains("5678"));
}

#[test]
fn test_error_classification() {
    assert!(error::PciError::RootComplexError.is_fatal());
    assert!(!error::PciError::DeviceNotFound.is_fatal());

    assert!(error::PciError::DeviceBlocked { vendor: 0, device: 0 }.is_security_related());
    assert!(!error::PciError::DeviceNotFound.is_security_related());

    assert!(error::PciError::DeviceNotFound.is_recoverable());
    assert!(!error::PciError::RootComplexError.is_recoverable());
}

#[test]
fn test_security_level_ordering() {
    assert!(security::SecurityLevel::Critical > security::SecurityLevel::High);
    assert!(security::SecurityLevel::High > security::SecurityLevel::Medium);
    assert!(security::SecurityLevel::Medium > security::SecurityLevel::Low);
}
