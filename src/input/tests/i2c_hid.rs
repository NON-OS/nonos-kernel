// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::i2c_hid::protocol::{
    HidCommand, HidRegister, SUPPORTED_COMMANDS,
    HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP, HID_USAGE_PAGE_BUTTON,
    HID_USAGE_TOUCHPAD, HID_USAGE_TOUCH_SCREEN, HID_USAGE_MOUSE, HID_USAGE_KEYBOARD,
    HID_USAGE_TIP_SWITCH, HID_USAGE_CONTACT_ID, HID_USAGE_X, HID_USAGE_Y,
    HID_USAGE_CONTACT_COUNT, HID_USAGE_BUTTON_PRIMARY, HID_USAGE_BUTTON_SECONDARY,
};

#[test]
fn test_hid_command_reset() {
    assert_eq!(HidCommand::Reset.opcode(), 0x01);
}

#[test]
fn test_hid_command_get_report() {
    assert_eq!(HidCommand::GetReport.opcode(), 0x02);
}

#[test]
fn test_hid_command_set_report() {
    assert_eq!(HidCommand::SetReport.opcode(), 0x03);
}

#[test]
fn test_hid_command_get_idle() {
    assert_eq!(HidCommand::GetIdle.opcode(), 0x04);
}

#[test]
fn test_hid_command_set_idle() {
    assert_eq!(HidCommand::SetIdle.opcode(), 0x05);
}

#[test]
fn test_hid_command_get_protocol() {
    assert_eq!(HidCommand::GetProtocol.opcode(), 0x06);
}

#[test]
fn test_hid_command_set_protocol() {
    assert_eq!(HidCommand::SetProtocol.opcode(), 0x07);
}

#[test]
fn test_hid_command_set_power() {
    assert_eq!(HidCommand::SetPower.opcode(), 0x08);
}

#[test]
fn test_hid_command_clone() {
    let cmd = HidCommand::Reset;
    let cloned = cmd.clone();
    assert_eq!(cmd, cloned);
}

#[test]
fn test_hid_command_copy() {
    let cmd = HidCommand::GetReport;
    let copied = cmd;
    assert_eq!(cmd, copied);
}

#[test]
fn test_hid_command_equality() {
    assert_eq!(HidCommand::Reset, HidCommand::Reset);
    assert_ne!(HidCommand::Reset, HidCommand::GetReport);
}

#[test]
fn test_hid_command_debug() {
    let cmd = HidCommand::Reset;
    let debug_str = alloc::format!("{:?}", cmd);
    assert!(debug_str.contains("Reset"));
}

#[test]
fn test_hid_register_hid_desc() {
    assert_eq!(HidRegister::HID_DESC.value, 0x0001);
}

#[test]
fn test_hid_register_new() {
    let reg = HidRegister::new(0x1234);
    assert_eq!(reg.value, 0x1234);
}

#[test]
fn test_hid_register_to_le_bytes() {
    let reg = HidRegister::new(0x1234);
    let bytes = reg.to_le_bytes();
    assert_eq!(bytes[0], 0x34);
    assert_eq!(bytes[1], 0x12);
}

#[test]
fn test_hid_register_to_le_bytes_zero() {
    let reg = HidRegister::new(0x0000);
    let bytes = reg.to_le_bytes();
    assert_eq!(bytes, [0x00, 0x00]);
}

#[test]
fn test_hid_register_to_le_bytes_max() {
    let reg = HidRegister::new(0xFFFF);
    let bytes = reg.to_le_bytes();
    assert_eq!(bytes, [0xFF, 0xFF]);
}

#[test]
fn test_hid_register_clone() {
    let reg = HidRegister::new(0xABCD);
    let cloned = reg.clone();
    assert_eq!(reg.value, cloned.value);
}

#[test]
fn test_hid_register_copy() {
    let reg = HidRegister::new(0xDEAD);
    let copied = reg;
    assert_eq!(reg.value, copied.value);
}

#[test]
fn test_hid_register_debug() {
    let reg = HidRegister::new(0x0001);
    let debug_str = alloc::format!("{:?}", reg);
    assert!(debug_str.contains("HidRegister"));
}

#[test]
fn test_supported_commands_count() {
    assert_eq!(SUPPORTED_COMMANDS.len(), 8);
}

#[test]
fn test_supported_commands_contains_reset() {
    assert!(SUPPORTED_COMMANDS.contains(&HidCommand::Reset));
}

#[test]
fn test_supported_commands_contains_get_report() {
    assert!(SUPPORTED_COMMANDS.contains(&HidCommand::GetReport));
}

#[test]
fn test_supported_commands_contains_set_report() {
    assert!(SUPPORTED_COMMANDS.contains(&HidCommand::SetReport));
}

#[test]
fn test_supported_commands_contains_set_power() {
    assert!(SUPPORTED_COMMANDS.contains(&HidCommand::SetPower));
}

#[test]
fn test_hid_usage_page_digitizer() {
    assert_eq!(HID_USAGE_PAGE_DIGITIZER, 0x0D);
}

#[test]
fn test_hid_usage_page_generic_desktop() {
    assert_eq!(HID_USAGE_PAGE_GENERIC_DESKTOP, 0x01);
}

#[test]
fn test_hid_usage_page_button() {
    assert_eq!(HID_USAGE_PAGE_BUTTON, 0x09);
}

#[test]
fn test_hid_usage_touchpad() {
    assert_eq!(HID_USAGE_TOUCHPAD, 0x05);
}

#[test]
fn test_hid_usage_touch_screen() {
    assert_eq!(HID_USAGE_TOUCH_SCREEN, 0x04);
}

#[test]
fn test_hid_usage_mouse() {
    assert_eq!(HID_USAGE_MOUSE, 0x02);
}

#[test]
fn test_hid_usage_keyboard() {
    assert_eq!(HID_USAGE_KEYBOARD, 0x06);
}

#[test]
fn test_hid_usage_tip_switch() {
    assert_eq!(HID_USAGE_TIP_SWITCH, 0x42);
}

#[test]
fn test_hid_usage_contact_id() {
    assert_eq!(HID_USAGE_CONTACT_ID, 0x51);
}

#[test]
fn test_hid_usage_x() {
    assert_eq!(HID_USAGE_X, 0x30);
}

#[test]
fn test_hid_usage_y() {
    assert_eq!(HID_USAGE_Y, 0x31);
}

#[test]
fn test_hid_usage_contact_count() {
    assert_eq!(HID_USAGE_CONTACT_COUNT, 0x54);
}

#[test]
fn test_hid_usage_button_primary() {
    assert_eq!(HID_USAGE_BUTTON_PRIMARY, 0x01);
}

#[test]
fn test_hid_usage_button_secondary() {
    assert_eq!(HID_USAGE_BUTTON_SECONDARY, 0x02);
}

#[test]
fn test_all_hid_commands_have_unique_opcodes() {
    let opcodes: alloc::vec::Vec<u8> = SUPPORTED_COMMANDS.iter()
        .map(|cmd| cmd.opcode())
        .collect();
    for (i, op1) in opcodes.iter().enumerate() {
        for (j, op2) in opcodes.iter().enumerate() {
            if i != j {
                assert_ne!(op1, op2);
            }
        }
    }
}

#[test]
fn test_hid_command_opcode_range() {
    for cmd in SUPPORTED_COMMANDS {
        let opcode = cmd.opcode();
        assert!(opcode >= 0x01 && opcode <= 0x08);
    }
}

#[test]
fn test_usage_pages_are_distinct() {
    assert_ne!(HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP);
    assert_ne!(HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_BUTTON);
    assert_ne!(HID_USAGE_PAGE_GENERIC_DESKTOP, HID_USAGE_PAGE_BUTTON);
}

#[test]
fn test_hid_register_sequence() {
    let reg1 = HidRegister::new(0x0001);
    let reg2 = HidRegister::new(0x0002);
    let reg3 = HidRegister::new(0x0003);
    assert!(reg1.value < reg2.value);
    assert!(reg2.value < reg3.value);
}
