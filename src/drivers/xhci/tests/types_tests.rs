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

#[cfg(test)]
mod tests {
    use crate::drivers::xhci::{constants, types};
    use core::mem;

    #[test]
    fn test_usb_device_descriptor_size() {
        assert_eq!(mem::size_of::<types::UsbDeviceDescriptor>(), 18);
    }

    #[test]
    fn test_usb_device_descriptor_validation() {
        let mut desc = types::UsbDeviceDescriptor::default();
        assert!(!desc.validate());

        desc.length = 18;
        desc.descriptor_type = constants::DESC_TYPE_DEVICE;
        assert!(desc.validate());
    }

    #[test]
    fn test_usb_version_parsing() {
        let mut desc = types::UsbDeviceDescriptor::default();
        desc.bcd_usb = 0x0200;

        let (major, minor) = desc.usb_version();
        assert_eq!(major, 2);
        assert_eq!(minor, 0);

        desc.bcd_usb = 0x0310;
        let (major, minor) = desc.usb_version();
        assert_eq!(major, 3);
        assert_eq!(minor, 0x10);
    }
}
