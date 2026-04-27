// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::i2c_hid::protocol::{
    HidCommand, HidRegister, HID_USAGE_BUTTON_PRIMARY, HID_USAGE_BUTTON_SECONDARY,
    HID_USAGE_CONTACT_COUNT, HID_USAGE_CONTACT_ID, HID_USAGE_KEYBOARD, HID_USAGE_MOUSE,
    HID_USAGE_PAGE_BUTTON, HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP,
    HID_USAGE_TIP_SWITCH, HID_USAGE_TOUCHPAD, HID_USAGE_TOUCH_SCREEN, HID_USAGE_X, HID_USAGE_Y,
    SUPPORTED_COMMANDS,
};
use crate::test::framework::TestResult;

pub(crate) fn test_hid_command_reset() -> TestResult {
    if HidCommand::Reset.opcode() != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_get_report() -> TestResult {
    if HidCommand::GetReport.opcode() != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_set_report() -> TestResult {
    if HidCommand::SetReport.opcode() != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_get_idle() -> TestResult {
    if HidCommand::GetIdle.opcode() != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_set_idle() -> TestResult {
    if HidCommand::SetIdle.opcode() != 0x05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_get_protocol() -> TestResult {
    if HidCommand::GetProtocol.opcode() != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_set_protocol() -> TestResult {
    if HidCommand::SetProtocol.opcode() != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_set_power() -> TestResult {
    if HidCommand::SetPower.opcode() != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_clone() -> TestResult {
    let cmd = HidCommand::Reset;
    let cloned = cmd.clone();
    if cmd != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_copy() -> TestResult {
    let cmd = HidCommand::GetReport;
    let copied = cmd;
    if cmd != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_equality() -> TestResult {
    if HidCommand::Reset != HidCommand::Reset {
        return TestResult::Fail;
    }
    if HidCommand::Reset == HidCommand::GetReport {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_debug() -> TestResult {
    let cmd = HidCommand::Reset;
    let debug_str = alloc::format!("{:?}", cmd);
    if !debug_str.contains("Reset") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_hid_desc() -> TestResult {
    if HidRegister::HID_DESC.value != 0x0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_new() -> TestResult {
    let reg = HidRegister::new(0x1234);
    if reg.value != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_to_le_bytes() -> TestResult {
    let reg = HidRegister::new(0x1234);
    let bytes = reg.to_le_bytes();
    if bytes[0] != 0x34 {
        return TestResult::Fail;
    }
    if bytes[1] != 0x12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_to_le_bytes_zero() -> TestResult {
    let reg = HidRegister::new(0x0000);
    let bytes = reg.to_le_bytes();
    if bytes != [0x00, 0x00] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_to_le_bytes_max() -> TestResult {
    let reg = HidRegister::new(0xFFFF);
    let bytes = reg.to_le_bytes();
    if bytes != [0xFF, 0xFF] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_clone() -> TestResult {
    let reg = HidRegister::new(0xABCD);
    let cloned = reg.clone();
    if reg.value != cloned.value {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_copy() -> TestResult {
    let reg = HidRegister::new(0xDEAD);
    let copied = reg;
    if reg.value != copied.value {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_debug() -> TestResult {
    let reg = HidRegister::new(0x0001);
    let debug_str = alloc::format!("{:?}", reg);
    if !debug_str.contains("HidRegister") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_commands_count() -> TestResult {
    if SUPPORTED_COMMANDS.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_commands_contains_reset() -> TestResult {
    if !SUPPORTED_COMMANDS.contains(&HidCommand::Reset) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_commands_contains_get_report() -> TestResult {
    if !SUPPORTED_COMMANDS.contains(&HidCommand::GetReport) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_commands_contains_set_report() -> TestResult {
    if !SUPPORTED_COMMANDS.contains(&HidCommand::SetReport) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_commands_contains_set_power() -> TestResult {
    if !SUPPORTED_COMMANDS.contains(&HidCommand::SetPower) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_page_digitizer() -> TestResult {
    if HID_USAGE_PAGE_DIGITIZER != 0x0D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_page_generic_desktop() -> TestResult {
    if HID_USAGE_PAGE_GENERIC_DESKTOP != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_page_button() -> TestResult {
    if HID_USAGE_PAGE_BUTTON != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_touchpad() -> TestResult {
    if HID_USAGE_TOUCHPAD != 0x05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_touch_screen() -> TestResult {
    if HID_USAGE_TOUCH_SCREEN != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_mouse() -> TestResult {
    if HID_USAGE_MOUSE != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_keyboard() -> TestResult {
    if HID_USAGE_KEYBOARD != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_tip_switch() -> TestResult {
    if HID_USAGE_TIP_SWITCH != 0x42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_contact_id() -> TestResult {
    if HID_USAGE_CONTACT_ID != 0x51 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_x() -> TestResult {
    if HID_USAGE_X != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_y() -> TestResult {
    if HID_USAGE_Y != 0x31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_contact_count() -> TestResult {
    if HID_USAGE_CONTACT_COUNT != 0x54 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_button_primary() -> TestResult {
    if HID_USAGE_BUTTON_PRIMARY != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_usage_button_secondary() -> TestResult {
    if HID_USAGE_BUTTON_SECONDARY != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_hid_commands_have_unique_opcodes() -> TestResult {
    let opcodes: alloc::vec::Vec<u8> = SUPPORTED_COMMANDS.iter().map(|cmd| cmd.opcode()).collect();
    for (i, op1) in opcodes.iter().enumerate() {
        for (j, op2) in opcodes.iter().enumerate() {
            if i != j {
                if op1 == op2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_hid_command_opcode_range() -> TestResult {
    for cmd in SUPPORTED_COMMANDS {
        let opcode = cmd.opcode();
        if !(opcode >= 0x01 && opcode <= 0x08) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_usage_pages_are_distinct() -> TestResult {
    if HID_USAGE_PAGE_DIGITIZER == HID_USAGE_PAGE_GENERIC_DESKTOP {
        return TestResult::Fail;
    }
    if HID_USAGE_PAGE_DIGITIZER == HID_USAGE_PAGE_BUTTON {
        return TestResult::Fail;
    }
    if HID_USAGE_PAGE_GENERIC_DESKTOP == HID_USAGE_PAGE_BUTTON {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_register_sequence() -> TestResult {
    let reg1 = HidRegister::new(0x0001);
    let reg2 = HidRegister::new(0x0002);
    let reg3 = HidRegister::new(0x0003);
    if !(reg1.value < reg2.value) {
        return TestResult::Fail;
    }
    if !(reg2.value < reg3.value) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
