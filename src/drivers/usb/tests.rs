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

#[cfg(test)]
mod tests {
    use super::super::constants::*;
    use super::super::descriptors::*;

    #[test]
    fn test_request_codes() {
        assert_eq!(REQ_GET_STATUS, 0x00);
        assert_eq!(REQ_CLEAR_FEATURE, 0x01);
        assert_eq!(REQ_SET_FEATURE, 0x03);
        assert_eq!(REQ_SET_ADDRESS, 0x05);
        assert_eq!(REQ_GET_DESCRIPTOR, 0x06);
        assert_eq!(REQ_SET_CONFIGURATION, 0x09);
    }

    #[test]
    fn test_request_type_bits() {
        assert_eq!(RT_DEV, 0x00);
        assert_eq!(RT_INTF, 0x01);
        assert_eq!(RT_EP, 0x02);
        assert_eq!(DIR_OUT, 0x00);
        assert_eq!(DIR_IN, 0x80);
        assert_eq!(TYPE_STD, 0x00);
        assert_eq!(TYPE_CLASS, 0x20);
        assert_eq!(TYPE_VENDOR, 0x40);
    }

    #[test]
    fn test_descriptor_types() {
        assert_eq!(DT_DEVICE, 1);
        assert_eq!(DT_CONFIG, 2);
        assert_eq!(DT_STRING, 3);
        assert_eq!(DT_INTERFACE, 4);
        assert_eq!(DT_ENDPOINT, 5);
    }

    #[test]
    fn test_endpoint_types() {
        assert_eq!(EP_TYPE_CONTROL, 0x00);
        assert_eq!(EP_TYPE_ISOCHRONOUS, 0x01);
        assert_eq!(EP_TYPE_BULK, 0x02);
        assert_eq!(EP_TYPE_INTERRUPT, 0x03);
    }

    #[test]
    fn test_class_codes() {
        assert_eq!(CLASS_HID, 0x03);
        assert_eq!(CLASS_MASS_STORAGE, 0x08);
        assert_eq!(CLASS_HUB, 0x09);
        assert_eq!(CLASS_AUDIO, 0x01);
        assert_eq!(CLASS_VIDEO, 0x0E);
    }

    #[test]
    fn test_device_descriptor_size() {
        assert_eq!(core::mem::size_of::<DeviceDescriptor>(), 18);
    }

    #[test]
    fn test_config_descriptor_size() {
        assert_eq!(core::mem::size_of::<ConfigDescriptorHeader>(), 9);
    }

    #[test]
    fn test_interface_descriptor_size() {
        assert_eq!(core::mem::size_of::<InterfaceDescriptor>(), 9);
    }

    #[test]
    fn test_endpoint_descriptor_size() {
        assert_eq!(core::mem::size_of::<EndpointDescriptor>(), 7);
    }

    #[test]
    fn test_string_table_default() {
        let table = UsbStringTable::new();
        assert!(table.manufacturer.is_none());
        assert!(table.product.is_none());
        assert!(table.serial.is_none());
        assert!(table.display_name().is_none());
    }

    #[test]
    fn test_default_lang_id() {
        assert_eq!(DEFAULT_LANG_ID, 0x0409);
    }

    #[test]
    fn test_transfer_timeouts() {
        assert_eq!(DEFAULT_CONTROL_TIMEOUT_US, 5_000_000);
        assert_eq!(DEFAULT_BULK_TIMEOUT_US, 5_000_000);
        assert_eq!(DEFAULT_INTERRUPT_TIMEOUT_US, 1_000_000);
    }

    #[test]
    fn test_endpoint_descriptor_methods() {
        let ep = EndpointDescriptor {
            b_length: 7,
            b_descriptor_type: DT_ENDPOINT,
            b_endpoint_address: 0x81,
            bm_attributes: EP_TYPE_BULK,
            w_max_packet_size: 512u16.to_le(),
            b_interval: 0,
        };

        assert_eq!(ep.endpoint_number(), 1);
        assert!(ep.is_in());
        assert!(!ep.is_out());
        assert!(ep.is_bulk());
        assert!(!ep.is_interrupt());
        assert!(!ep.is_control());
        assert!(!ep.is_isochronous());
        assert_eq!(ep.max_packet_size(), 512);
        assert_eq!(ep.transfer_type_name(), "Bulk");
    }

    #[test]
    fn test_endpoint_out() {
        let ep = EndpointDescriptor {
            b_length: 7,
            b_descriptor_type: DT_ENDPOINT,
            b_endpoint_address: 0x02,
            bm_attributes: EP_TYPE_INTERRUPT,
            w_max_packet_size: 8u16.to_le(),
            b_interval: 10,
        };

        assert_eq!(ep.endpoint_number(), 2);
        assert!(!ep.is_in());
        assert!(ep.is_out());
        assert!(ep.is_interrupt());
        assert!(!ep.is_bulk());
    }
}
