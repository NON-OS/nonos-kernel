use crate::input::i2c_hid::descriptor::{
    HidDescriptor, FieldLocation, ContactFields, TouchpadLayout,
};

#[test]
fn test_hid_descriptor_default() {
    let desc = HidDescriptor::default();
    assert_eq!(desc.hid_descriptor_length, 30);
    assert_eq!(desc.bcd_version, 0x0100);
    assert_eq!(desc.report_descriptor_length, 0);
    assert_eq!(desc.report_descriptor_register, 0x0002);
    assert_eq!(desc.input_register, 0x0003);
    assert_eq!(desc.max_input_length, 64);
    assert_eq!(desc.output_register, 0x0004);
    assert_eq!(desc.max_output_length, 64);
    assert_eq!(desc.command_register, 0x0005);
    assert_eq!(desc.data_register, 0x0006);
    assert_eq!(desc.vendor_id, 0);
    assert_eq!(desc.product_id, 0);
    assert_eq!(desc.version_id, 0);
}

#[test]
fn test_hid_descriptor_parse_valid() {
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
    assert!(desc.is_some());
    let desc = desc.unwrap();
    assert_eq!(desc.hid_descriptor_length, 30);
    assert_eq!(desc.bcd_version, 0x0100);
    assert_eq!(desc.report_descriptor_length, 0x0050);
    assert_eq!(desc.report_descriptor_register, 0x0002);
    assert_eq!(desc.input_register, 0x0003);
    assert_eq!(desc.max_input_length, 0x0040);
    assert_eq!(desc.vendor_id, 0x12AB);
    assert_eq!(desc.product_id, 0x34CD);
}

#[test]
fn test_hid_descriptor_parse_too_short() {
    let data = [0u8; 20];
    let desc = HidDescriptor::parse(&data);
    assert!(desc.is_none());
}

#[test]
fn test_hid_descriptor_parse_invalid_length() {
    let mut data = [0u8; 30];
    data[0] = 20;
    data[1] = 0;
    let desc = HidDescriptor::parse(&data);
    assert!(desc.is_none());
}

#[test]
fn test_hid_descriptor_parse_invalid_version() {
    let mut data = [0u8; 30];
    data[0] = 30;
    data[1] = 0;
    data[2] = 0x00;
    data[3] = 0x02;
    let desc = HidDescriptor::parse(&data);
    assert!(desc.is_none());
}

#[test]
fn test_field_location_default() {
    let field = FieldLocation::default();
    assert_eq!(field.bit_offset, 0);
    assert_eq!(field.bit_size, 0);
}

#[test]
fn test_field_location_is_valid() {
    let valid = FieldLocation { bit_offset: 0, bit_size: 8 };
    assert!(valid.is_valid());

    let invalid = FieldLocation { bit_offset: 0, bit_size: 0 };
    assert!(!invalid.is_valid());
}

#[test]
fn test_field_location_extract_single_bit() {
    let field = FieldLocation { bit_offset: 0, bit_size: 1 };
    let data = [0b00000001];
    assert_eq!(field.extract(&data), 1);

    let data = [0b00000000];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_field_location_extract_single_bit_offset() {
    let field = FieldLocation { bit_offset: 3, bit_size: 1 };
    let data = [0b00001000];
    assert_eq!(field.extract(&data), 1);

    let data = [0b00000000];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_field_location_extract_byte_aligned() {
    let field = FieldLocation { bit_offset: 0, bit_size: 8 };
    let data = [0xAB];
    assert_eq!(field.extract(&data), 0xAB);
}

#[test]
fn test_field_location_extract_16bit_aligned() {
    let field = FieldLocation { bit_offset: 0, bit_size: 16 };
    let data = [0x34, 0x12];
    assert_eq!(field.extract(&data), 0x1234);
}

#[test]
fn test_field_location_extract_empty_data() {
    let field = FieldLocation { bit_offset: 0, bit_size: 8 };
    let data: [u8; 0] = [];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_field_location_extract_invalid() {
    let field = FieldLocation { bit_offset: 0, bit_size: 0 };
    let data = [0xFF];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_field_location_extract_out_of_bounds() {
    let field = FieldLocation { bit_offset: 16, bit_size: 8 };
    let data = [0xFF];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_contact_fields_default() {
    let fields = ContactFields::default();
    assert!(!fields.tip_switch.is_valid());
    assert!(!fields.confidence.is_valid());
    assert!(!fields.contact_id.is_valid());
    assert!(!fields.x.is_valid());
    assert!(!fields.y.is_valid());
    assert!(!fields.pressure.is_valid());
    assert!(!fields.width.is_valid());
    assert!(!fields.height.is_valid());
}

#[test]
fn test_contact_fields_structure() {
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
    assert!(fields.tip_switch.is_valid());
    assert!(fields.x.is_valid());
    assert!(fields.y.is_valid());
}

#[test]
fn test_touchpad_layout_default() {
    let layout = TouchpadLayout::default();
    assert_eq!(layout.report_id, 0);
    assert!(!layout.scan_time.is_valid());
    assert!(!layout.contact_count.is_valid());
    assert!(!layout.button.is_valid());
    assert_eq!(layout.contacts.len(), 5);
    assert_eq!(layout.contact_field_size, 0);
    assert_eq!(layout.total_report_size, 0);
}

#[test]
fn test_touchpad_layout_contacts_array() {
    let layout = TouchpadLayout::default();
    for contact in &layout.contacts {
        assert!(!contact.tip_switch.is_valid());
        assert!(!contact.x.is_valid());
        assert!(!contact.y.is_valid());
    }
}

#[test]
fn test_field_location_clone() {
    let field = FieldLocation { bit_offset: 10, bit_size: 16 };
    let cloned = field.clone();
    assert_eq!(cloned.bit_offset, 10);
    assert_eq!(cloned.bit_size, 16);
}

#[test]
fn test_field_location_copy() {
    let field = FieldLocation { bit_offset: 20, bit_size: 8 };
    let copied = field;
    assert_eq!(copied.bit_offset, 20);
    assert_eq!(copied.bit_size, 8);
}

#[test]
fn test_contact_fields_clone() {
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
    assert_eq!(cloned.tip_switch.bit_offset, 0);
    assert_eq!(cloned.x.bit_offset, 8);
    assert_eq!(cloned.y.bit_offset, 24);
}

#[test]
fn test_hid_descriptor_clone() {
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
    assert_eq!(cloned.vendor_id, 0x1234);
    assert_eq!(cloned.product_id, 0x5678);
    assert_eq!(cloned.max_input_length, 128);
}

#[test]
fn test_touchpad_layout_clone() {
    let mut layout = TouchpadLayout::default();
    layout.report_id = 5;
    layout.total_report_size = 64;
    let cloned = layout.clone();
    assert_eq!(cloned.report_id, 5);
    assert_eq!(cloned.total_report_size, 64);
}

#[test]
fn test_field_location_extract_multi_byte() {
    let field = FieldLocation { bit_offset: 8, bit_size: 16 };
    let data = [0x00, 0x34, 0x12];
    assert_eq!(field.extract(&data), 0x1234);
}

#[test]
fn test_field_location_extract_nibble() {
    let field = FieldLocation { bit_offset: 4, bit_size: 4 };
    let data = [0xAB];
    let result = field.extract(&data);
    assert_eq!(result, 0x0A);
}

#[test]
fn test_field_location_bit_7() {
    let field = FieldLocation { bit_offset: 7, bit_size: 1 };
    let data = [0x80];
    assert_eq!(field.extract(&data), 1);

    let data = [0x7F];
    assert_eq!(field.extract(&data), 0);
}

#[test]
fn test_hid_descriptor_registers() {
    let desc = HidDescriptor::default();
    assert!(desc.report_descriptor_register < desc.input_register);
    assert!(desc.input_register < desc.output_register);
    assert!(desc.output_register < desc.command_register);
    assert!(desc.command_register < desc.data_register);
}

#[test]
fn test_touchpad_layout_structure() {
    let layout = TouchpadLayout {
        report_id: 1,
        scan_time: FieldLocation { bit_offset: 8, bit_size: 16 },
        contact_count: FieldLocation { bit_offset: 24, bit_size: 8 },
        button: FieldLocation { bit_offset: 32, bit_size: 1 },
        contacts: [ContactFields::default(); 5],
        contact_field_size: 40,
        total_report_size: 240,
    };
    assert_eq!(layout.report_id, 1);
    assert!(layout.scan_time.is_valid());
    assert!(layout.contact_count.is_valid());
    assert!(layout.button.is_valid());
}
