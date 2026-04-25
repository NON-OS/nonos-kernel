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
use crate::test::framework::TestResult;

pub(crate) fn test_device_descriptor_size() -> TestResult {
    if core::mem::size_of::<DeviceDescriptor>() != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_descriptor_header_size() -> TestResult {
    if core::mem::size_of::<ConfigDescriptorHeader>() != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interface_descriptor_size() -> TestResult {
    if core::mem::size_of::<InterfaceDescriptor>() != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_size() -> TestResult {
    if core::mem::size_of::<EndpointDescriptor>() != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_in_direction() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if !ep.is_in() {
        return TestResult::Fail;
    }
    if ep.is_out() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_out_direction() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x02,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if ep.is_in() {
        return TestResult::Fail;
    }
    if !ep.is_out() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_number() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x83,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if ep.endpoint_number() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_bulk_type() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if !ep.is_bulk() {
        return TestResult::Fail;
    }
    if ep.is_interrupt() {
        return TestResult::Fail;
    }
    if ep.is_control() {
        return TestResult::Fail;
    }
    if ep.is_isochronous() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_interrupt_type() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_INTERRUPT,
        w_max_packet_size: 8u16.to_le(),
        b_interval: 10,
    };

    if ep.is_bulk() {
        return TestResult::Fail;
    }
    if !ep.is_interrupt() {
        return TestResult::Fail;
    }
    if ep.is_control() {
        return TestResult::Fail;
    }
    if ep.is_isochronous() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_control_type() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x00,
        bm_attributes: EP_TYPE_CONTROL,
        w_max_packet_size: 64u16.to_le(),
        b_interval: 0,
    };

    if ep.is_bulk() {
        return TestResult::Fail;
    }
    if ep.is_interrupt() {
        return TestResult::Fail;
    }
    if !ep.is_control() {
        return TestResult::Fail;
    }
    if ep.is_isochronous() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_isochronous_type() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_ISOCHRONOUS,
        w_max_packet_size: 1024u16.to_le(),
        b_interval: 1,
    };

    if ep.is_bulk() {
        return TestResult::Fail;
    }
    if ep.is_interrupt() {
        return TestResult::Fail;
    }
    if ep.is_control() {
        return TestResult::Fail;
    }
    if !ep.is_isochronous() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_max_packet_size() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if ep.max_packet_size() != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_transfer_type_name_control() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x00,
        bm_attributes: EP_TYPE_CONTROL,
        w_max_packet_size: 64u16.to_le(),
        b_interval: 0,
    };

    if ep.transfer_type_name() != "Control" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_transfer_type_name_bulk() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_BULK,
        w_max_packet_size: 512u16.to_le(),
        b_interval: 0,
    };

    if ep.transfer_type_name() != "Bulk" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_transfer_type_name_interrupt() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_INTERRUPT,
        w_max_packet_size: 8u16.to_le(),
        b_interval: 10,
    };

    if ep.transfer_type_name() != "Interrupt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_descriptor_transfer_type_name_isochronous() -> TestResult {
    let ep = EndpointDescriptor {
        b_length: 7,
        b_descriptor_type: DT_ENDPOINT,
        b_endpoint_address: 0x81,
        bm_attributes: EP_TYPE_ISOCHRONOUS,
        w_max_packet_size: 1024u16.to_le(),
        b_interval: 1,
    };

    if ep.transfer_type_name() != "Isochronous" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_table_new() -> TestResult {
    let table = UsbStringTable::new();
    if table.manufacturer.is_some() {
        return TestResult::Fail;
    }
    if table.product.is_some() {
        return TestResult::Fail;
    }
    if table.serial.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_table_display_name_empty() -> TestResult {
    let table = UsbStringTable::new();
    if table.display_name().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_number_range() -> TestResult {
    for addr in 0x80..=0x8F {
        let ep = EndpointDescriptor {
            b_length: 7,
            b_descriptor_type: DT_ENDPOINT,
            b_endpoint_address: addr,
            bm_attributes: EP_TYPE_BULK,
            w_max_packet_size: 512u16.to_le(),
            b_interval: 0,
        };
        if ep.endpoint_number() > 15 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_direction_mask() -> TestResult {
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

    if in_ep.endpoint_number() != out_ep.endpoint_number() {
        return TestResult::Fail;
    }
    if !in_ep.is_in() {
        return TestResult::Fail;
    }
    if !out_ep.is_out() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
