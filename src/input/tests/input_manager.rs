use crate::input::{InputManager, InputSource};
use crate::test::framework::TestResult;

pub(crate) fn test_input_source_enum_values() -> TestResult {
    if InputSource::PS2 != InputSource::PS2 {
        return TestResult::Fail;
    }
    if InputSource::USB != InputSource::USB {
        return TestResult::Fail;
    }
    if InputSource::I2C != InputSource::I2C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_not_equal() -> TestResult {
    if InputSource::PS2 == InputSource::USB {
        return TestResult::Fail;
    }
    if InputSource::PS2 == InputSource::I2C {
        return TestResult::Fail;
    }
    if InputSource::USB == InputSource::I2C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_clone() -> TestResult {
    let source = InputSource::PS2;
    let cloned = source.clone();
    if source != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_copy() -> TestResult {
    let source = InputSource::USB;
    let copied = source;
    if source != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_debug() -> TestResult {
    let source = InputSource::PS2;
    let debug_str = alloc::format!("{:?}", source);
    if !debug_str.contains("PS2") {
        return TestResult::Fail;
    }

    let source = InputSource::USB;
    let debug_str = alloc::format!("{:?}", source);
    if !debug_str.contains("USB") {
        return TestResult::Fail;
    }

    let source = InputSource::I2C;
    let debug_str = alloc::format!("{:?}", source);
    if !debug_str.contains("I2C") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_manager_struct_creation() -> TestResult {
    let manager = InputManager::detect();
    let _source = manager.source();
    TestResult::Pass
}

pub(crate) fn test_input_manager_source_returns_valid_source() -> TestResult {
    let manager = InputManager::detect();
    let source = manager.source();
    if !(source == InputSource::PS2 || source == InputSource::USB || source == InputSource::I2C) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_all_variants() -> TestResult {
    let sources = [InputSource::PS2, InputSource::USB, InputSource::I2C];
    if sources.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_pattern_matching() -> TestResult {
    let source = InputSource::PS2;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    if result != "ps2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_usb_pattern() -> TestResult {
    let source = InputSource::USB;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    if result != "usb" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_source_i2c_pattern() -> TestResult {
    let source = InputSource::I2C;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    if result != "i2c" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
