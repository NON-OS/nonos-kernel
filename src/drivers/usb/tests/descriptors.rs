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

use crate::drivers::usb::constants::*;
use crate::drivers::usb::descriptors::*;

#[test]
fn test_device_descriptor_size() {
    assert_eq!(core::mem::size_of::<DeviceDescriptor>(), 18);
}

#[test]
fn test_config_descriptor_header_size() {
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
fn test_endpoint_descriptor_in_direction() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert!(ep.is_in());
    assert!(!ep.is_out());
}

#[test]
fn test_endpoint_descriptor_out_direction() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x02,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert!(!ep.is_in());
    assert!(ep.is_out());
}

#[test]
fn test_endpoint_descriptor_number() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x83,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert_eq!(ep.endpoint_number(), 3);
}

#[test]
fn test_endpoint_descriptor_bulk_type() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert!(ep.is_bulk());
    assert!(!ep.is_interrupt());
    assert!(!ep.is_control());
    assert!(!ep.is_isochronous());
}

#[test]
fn test_endpoint_descriptor_interrupt_type() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_INTERRUPT,
        w_max_packet_size: 8u16.to_le(),
        b_interval: 10,
    };

    assert!(!ep.is_bulk());
    assert!(ep.is_interrupt());
    assert!(!ep.is_control());
    assert!(!ep.is_isochronous());
}

#[test]
fn test_endpoint_descriptor_control_type() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x00,
        bm_attributes: EP_TYPE_CONTROL,
        w_max_packet_size: 64u16.to_le(),
        b_interval: 0,
    };

    assert!(!ep.is_bulk());
    assert!(!ep.is_interrupt());
    assert!(ep.is_control());
    assert!(!ep.is_isochronous());
}

#[test]
fn test_endpoint_descriptor_isochronous_type() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_ISOCHRONOUS,
        w_max_packet_size: 1024u16.to_le(),
        b_interval: 1,
    };

    assert!(!ep.is_bulk());
    assert!(!ep.is_interrupt());
    assert!(!ep.is_control());
    assert!(ep.is_isochronous());
}

#[test]
fn test_endpoint_descriptor_max_packet_size() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert_eq!(ep.max_packet_size(), 512);
}

#[test]
fn test_endpoint_descriptor_transfer_type_name_control() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x00,
        bm_attributes: EP_TYPE_CONTROL,
        w_max_packet_size: 64u16.to_le(),
        b_interval: 0,
    };

    assert_eq!(ep.transfer_type_name(), "Control");
}

#[test]
fn test_endpoint_descriptor_transfer_type_name_bulk() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert_eq!(ep.transfer_type_name(), "Bulk");
}

#[test]
fn test_endpoint_descriptor_transfer_type_name_interrupt() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_INTERRUPT,
        w_max_packet_size: 8u16.to_le(),
        b_interval: 10,
    };

    assert_eq!(ep.transfer_type_name(), "Interrupt");
}

#[test]
fn test_endpoint_descriptor_transfer_type_name_isochronous() {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_ISOCHRONOUS,
        w_max_packet_size: 1024u16.to_le(),
        b_interval: 1,
    };

    assert_eq!(ep.transfer_type_name(), "Isochronous");
}

#[test]
fn test_string_table_new() {
    let table = UsbStringTable::new();
    assert!(table.manufacturer.is_none());
    assert!(table.product.is_none());
    assert!(table.serial.is_none());
}

#[test]
fn test_string_table_display_name_empty() {
    let table = UsbStringTable::new();
    assert!(table.display_name().is_none());
}

#[test]
fn test_endpoint_number_range() {
    for addr in 0x80..=0x8F {
        let ep = EndpointDescriptor {
            b_length: 7,
            b_descriptor_type: DT_ENDPOINT,
            b_endpoint_address: addr,
            bm_attributes: EP_TYPE_BULK,
            w_max_packet_size: 512u16.to_le(),
            b_interval: 0,
        };
        assert!(ep.endpoint_number() <= 15);
    }
}

#[test]
fn test_endpoint_direction_mask() {
    let in_ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    let out_ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x01,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    assert_eq!(in_ep.endpoint_number(), out_ep.endpoint_number());
    assert!(in_ep.is_in());
    assert!(out_ep.is_out());
}
