use crate::input::i2c_hid::descriptor::{
    ContactFields, FieldLocation, HidDescriptor, TouchpadLayout,
};
use crate::test::framework::TestResult;

pub(crate) fn test_hid_descriptor_default() -> TestResult {
    let desc = HidDescriptor::default();
    if desc.hid_descriptor_length != 30 {
        return TestResult::Fail;
    }
    if desc.bcd_version != 0x0100 {
        return TestResult::Fail;
    }
    if desc.report_descriptor_length != 0 {
        return TestResult::Fail;
    }
    if desc.report_descriptor_register != 0x0002 {
        return TestResult::Fail;
    }
    if desc.input_register != 0x0003 {
        return TestResult::Fail;
    }
    if desc.max_input_length != 64 {
        return TestResult::Fail;
    }
    if desc.output_register != 0x0004 {
        return TestResult::Fail;
    }
    if desc.max_output_length != 64 {
        return TestResult::Fail;
    }
    if desc.command_register != 0x0005 {
        return TestResult::Fail;
    }
    if desc.data_register != 0x0006 {
        return TestResult::Fail;
    }
    if desc.vendor_id != 0 {
        return TestResult::Fail;
    }
    if desc.product_id != 0 {
        return TestResult::Fail;
    }
    if desc.version_id != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_parse_valid() -> TestResult {
    let mut data = [0u8; 30];
    data[0] = 30;
    data[1] = 0;
    data[2] = 0x00;
    data[3] = 0x01;
    data[4] = 0x50;
    data[5] = 0x00;
    data[6] = 0x02;
    data[7] = 0x00;
    data[8] = 0x03;
    data[9] = 0x00;
    data[10] = 0x40;
    data[11] = 0x00;
    data[12] = 0x04;
    data[13] = 0x00;
    data[14] = 0x40;
    data[15] = 0x00;
    data[16] = 0x05;
    data[17] = 0x00;
    data[18] = 0x06;
    data[19] = 0x00;
    data[20] = 0xAB;
    data[21] = 0x12;
    data[22] = 0xCD;
    data[23] = 0x34;
    data[24] = 0x01;
    data[25] = 0x00;

    let desc = HidDescriptor::parse(&data);
    if !desc.is_some() {
        return TestResult::Fail;
    }
    let desc = desc.unwrap();
    if desc.hid_descriptor_length != 30 {
        return TestResult::Fail;
    }
    if desc.bcd_version != 0x0100 {
        return TestResult::Fail;
    }
    if desc.report_descriptor_length != 0x0050 {
        return TestResult::Fail;
    }
    if desc.report_descriptor_register != 0x0002 {
        return TestResult::Fail;
    }
    if desc.input_register != 0x0003 {
        return TestResult::Fail;
    }
    if desc.max_input_length != 0x0040 {
        return TestResult::Fail;
    }
    if desc.vendor_id != 0x12AB {
        return TestResult::Fail;
    }
    if desc.product_id != 0x34CD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_parse_too_short() -> TestResult {
    let data = [0u8; 20];
    let desc = HidDescriptor::parse(&data);
    if !desc.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_parse_invalid_length() -> TestResult {
    let mut data = [0u8; 30];
    data[0] = 20;
    data[1] = 0;
    let desc = HidDescriptor::parse(&data);
    if !desc.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_parse_invalid_version() -> TestResult {
    let mut data = [0u8; 30];
    data[0] = 30;
    data[1] = 0;
    data[2] = 0x00;
    data[3] = 0x02;
    let desc = HidDescriptor::parse(&data);
    if !desc.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_default() -> TestResult {
    let field = FieldLocation::default();
    if field.bit_offset != 0 {
        return TestResult::Fail;
    }
    if field.bit_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_is_valid() -> TestResult {
    let valid = FieldLocation { bit_offset: 0, bit_size: 8 };
    if !valid.is_valid() {
        return TestResult::Fail;
    }

    let invalid = FieldLocation { bit_offset: 0, bit_size: 0 };
    if invalid.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_single_bit() -> TestResult {
    let field = FieldLocation { bit_offset: 0, bit_size: 1 };
    let data = [0b00000001];
    if field.extract(&data) != 1 {
        return TestResult::Fail;
    }

    let data = [0b00000000];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_single_bit_offset() -> TestResult {
    let field = FieldLocation { bit_offset: 3, bit_size: 1 };
    let data = [0b00001000];
    if field.extract(&data) != 1 {
        return TestResult::Fail;
    }

    let data = [0b00000000];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_byte_aligned() -> TestResult {
    let field = FieldLocation { bit_offset: 0, bit_size: 8 };
    let data = [0xAB];
    if field.extract(&data) != 0xAB {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_16bit_aligned() -> TestResult {
    let field = FieldLocation { bit_offset: 0, bit_size: 16 };
    let data = [0x34, 0x12];
    if field.extract(&data) != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_empty_data() -> TestResult {
    let field = FieldLocation { bit_offset: 0, bit_size: 8 };
    let data: [u8; 0] = [];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_invalid() -> TestResult {
    let field = FieldLocation { bit_offset: 0, bit_size: 0 };
    let data = [0xFF];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_out_of_bounds() -> TestResult {
    let field = FieldLocation { bit_offset: 16, bit_size: 8 };
    let data = [0xFF];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contact_fields_default() -> TestResult {
    let fields = ContactFields::default();
    if fields.tip_switch.is_valid() {
        return TestResult::Fail;
    }
    if fields.confidence.is_valid() {
        return TestResult::Fail;
    }
    if fields.contact_id.is_valid() {
        return TestResult::Fail;
    }
    if fields.x.is_valid() {
        return TestResult::Fail;
    }
    if fields.y.is_valid() {
        return TestResult::Fail;
    }
    if fields.pressure.is_valid() {
        return TestResult::Fail;
    }
    if fields.width.is_valid() {
        return TestResult::Fail;
    }
    if fields.height.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contact_fields_structure() -> TestResult {
    let fields = ContactFields {
        tip_switch: FieldLocation { bit_offset: 0, bit_size: 1 },
        confidence: FieldLocation { bit_offset: 1, bit_size: 1 },
        contact_id: FieldLocation { bit_offset: 8, bit_size: 8 },
        x: FieldLocation { bit_offset: 16, bit_size: 16 },
        y: FieldLocation { bit_offset: 32, bit_size: 16 },
        pressure: FieldLocation { bit_offset: 48, bit_size: 8 },
        width: FieldLocation { bit_offset: 56, bit_size: 8 },
        height: FieldLocation { bit_offset: 64, bit_size: 8 },
    };
    if !fields.tip_switch.is_valid() {
        return TestResult::Fail;
    }
    if !fields.x.is_valid() {
        return TestResult::Fail;
    }
    if !fields.y.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_layout_default() -> TestResult {
    let layout = TouchpadLayout::default();
    if layout.report_id != 0 {
        return TestResult::Fail;
    }
    if layout.scan_time.is_valid() {
        return TestResult::Fail;
    }
    if layout.contact_count.is_valid() {
        return TestResult::Fail;
    }
    if layout.button.is_valid() {
        return TestResult::Fail;
    }
    if layout.contacts.len() != 5 {
        return TestResult::Fail;
    }
    if layout.contact_field_size != 0 {
        return TestResult::Fail;
    }
    if layout.total_report_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_layout_contacts_array() -> TestResult {
    let layout = TouchpadLayout::default();
    for contact in &layout.contacts {
        if contact.tip_switch.is_valid() {
            return TestResult::Fail;
        }
        if contact.x.is_valid() {
            return TestResult::Fail;
        }
        if contact.y.is_valid() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_clone() -> TestResult {
    let field = FieldLocation { bit_offset: 10, bit_size: 16 };
    let cloned = field.clone();
    if cloned.bit_offset != 10 {
        return TestResult::Fail;
    }
    if cloned.bit_size != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_copy() -> TestResult {
    let field = FieldLocation { bit_offset: 20, bit_size: 8 };
    let copied = field;
    if copied.bit_offset != 20 {
        return TestResult::Fail;
    }
    if copied.bit_size != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_contact_fields_clone() -> TestResult {
    let fields = ContactFields {
        tip_switch: FieldLocation { bit_offset: 0, bit_size: 1 },
        confidence: FieldLocation::default(),
        contact_id: FieldLocation::default(),
        x: FieldLocation { bit_offset: 8, bit_size: 16 },
        y: FieldLocation { bit_offset: 24, bit_size: 16 },
        pressure: FieldLocation::default(),
        width: FieldLocation::default(),
        height: FieldLocation::default(),
    };
    let cloned = fields.clone();
    if cloned.tip_switch.bit_offset != 0 {
        return TestResult::Fail;
    }
    if cloned.x.bit_offset != 8 {
        return TestResult::Fail;
    }
    if cloned.y.bit_offset != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_clone() -> TestResult {
    let desc = HidDescriptor {
        hid_descriptor_length: 30,
        bcd_version: 0x0100,
        report_descriptor_length: 100,
        report_descriptor_register: 0x0002,
        input_register: 0x0003,
        max_input_length: 128,
        output_register: 0x0004,
        max_output_length: 64,
        command_register: 0x0005,
        data_register: 0x0006,
        vendor_id: 0x1234,
        product_id: 0x5678,
        version_id: 0x0001,
    };
    let cloned = desc.clone();
    if cloned.vendor_id != 0x1234 {
        return TestResult::Fail;
    }
    if cloned.product_id != 0x5678 {
        return TestResult::Fail;
    }
    if cloned.max_input_length != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_layout_clone() -> TestResult {
    let mut layout = TouchpadLayout::default();
    layout.report_id = 5;
    layout.total_report_size = 64;
    let cloned = layout.clone();
    if cloned.report_id != 5 {
        return TestResult::Fail;
    }
    if cloned.total_report_size != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_multi_byte() -> TestResult {
    let field = FieldLocation { bit_offset: 8, bit_size: 16 };
    let data = [0x00, 0x34, 0x12];
    if field.extract(&data) != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_extract_nibble() -> TestResult {
    let field = FieldLocation { bit_offset: 4, bit_size: 4 };
    let data = [0xAB];
    let result = field.extract(&data);
    if result != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_location_bit_7() -> TestResult {
    let field = FieldLocation { bit_offset: 7, bit_size: 1 };
    let data = [0x80];
    if field.extract(&data) != 1 {
        return TestResult::Fail;
    }

    let data = [0x7F];
    if field.extract(&data) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_registers() -> TestResult {
    let desc = HidDescriptor::default();
    if !(desc.report_descriptor_register < desc.input_register) {
        return TestResult::Fail;
    }
    if !(desc.input_register < desc.output_register) {
        return TestResult::Fail;
    }
    if !(desc.output_register < desc.command_register) {
        return TestResult::Fail;
    }
    if !(desc.command_register < desc.data_register) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_layout_structure() -> TestResult {
    let layout = TouchpadLayout {
        report_id: 1,
        scan_time: FieldLocation { bit_offset: 8, bit_size: 16 },
        contact_count: FieldLocation { bit_offset: 24, bit_size: 8 },
        button: FieldLocation { bit_offset: 32, bit_size: 1 },
        contacts: [ContactFields::default(); 5],
        contact_field_size: 40,
        total_report_size: 240,
    };
    if layout.report_id != 1 {
        return TestResult::Fail;
    }
    if !layout.scan_time.is_valid() {
        return TestResult::Fail;
    }
    if !layout.contact_count.is_valid() {
        return TestResult::Fail;
    }
    if !layout.button.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
