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
use super::error::DriverError;

pub fn validate_pci_access(
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> Result<(), DriverError> {
    if bus > PCI_MAX_BUS {
        return Err(DriverError::InvalidPciAccess);
    }

    if device > PCI_MAX_DEVICE {
        return Err(DriverError::InvalidPciAccess);
    }

    if function > PCI_MAX_FUNCTION {
        return Err(DriverError::InvalidPciAccess);
    }

    if u16::from(offset) >= PCI_CONFIG_SPACE_SIZE {
        return Err(DriverError::InvalidPciAccess);
    }

    Ok(())
}

pub fn validate_pci_extended_access(
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> Result<(), DriverError> {
    if bus > PCI_MAX_BUS {
        return Err(DriverError::InvalidPciAccess);
    }

    if device > PCI_MAX_DEVICE {
        return Err(DriverError::InvalidPciAccess);
    }

    if function > PCI_MAX_FUNCTION {
        return Err(DriverError::InvalidPciAccess);
    }

    if offset >= PCI_EXTENDED_CONFIG_SIZE {
        return Err(DriverError::InvalidPciAccess);
    }

    Ok(())
}

pub fn is_config_write_allowed(offset: u8) -> bool {
    !PROTECTED_CONFIG_OFFSETS.contains(&offset)
}

pub fn is_sensitive_config_read(offset: u8) -> bool {
    matches!(offset, 0x34 | 0x40..=0xFF)
}

pub fn build_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let enable_bit = 1u32 << 31;
    let bus_bits = (bus as u32) << 16;
    let device_bits = (device as u32 & 0x1F) << 11;
    let function_bits = (function as u32 & 0x07) << 8;
    let offset_bits = (offset as u32) & 0xFC;

    enable_bit | bus_bits | device_bits | function_bits | offset_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pci_access_valid() {
        assert!(validate_pci_access(0, 0, 0, 0).is_ok());
        assert!(validate_pci_access(255, 31, 7, 255).is_ok());
        assert!(validate_pci_access(0, 0, 0, 64).is_ok());
    }

    #[test]
    fn test_validate_pci_access_invalid_device() {
        assert!(validate_pci_access(0, 32, 0, 0).is_err());
    }

    #[test]
    fn test_validate_pci_access_invalid_function() {
        assert!(validate_pci_access(0, 0, 8, 0).is_err());
    }

    #[test]
    fn test_config_write_allowed() {
        assert!(is_config_write_allowed(0x00));
        assert!(is_config_write_allowed(0x10));

        assert!(!is_config_write_allowed(0x04));
        assert!(!is_config_write_allowed(0x3C));
    }

    #[test]
    fn test_build_config_address() {
        let addr = build_config_address(0, 0, 0, 0);
        assert_eq!(addr, 0x8000_0000);

        let addr = build_config_address(1, 2, 3, 4);
        assert_eq!(addr, 0x8001_1304);
    }
}
