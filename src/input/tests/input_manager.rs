use crate::input::{InputSource, InputManager};

#[test]
fn test_input_source_enum_values() {
    assert_eq!(InputSource::PS2, InputSource::PS2);
    assert_eq!(InputSource::USB, InputSource::USB);
    assert_eq!(InputSource::I2C, InputSource::I2C);
}

#[test]
fn test_input_source_not_equal() {
    assert_ne!(InputSource::PS2, InputSource::USB);
    assert_ne!(InputSource::PS2, InputSource::I2C);
    assert_ne!(InputSource::USB, InputSource::I2C);
}

#[test]
fn test_input_source_clone() {
    let source = InputSource::PS2;
    let cloned = source.clone();
    assert_eq!(source, cloned);
}

#[test]
fn test_input_source_copy() {
    let source = InputSource::USB;
    let copied = source;
    assert_eq!(source, copied);
}

#[test]
fn test_input_source_debug() {
    let source = InputSource::PS2;
    let debug_str = alloc::format!("{:?}", source);
    assert!(debug_str.contains("PS2"));

    let source = InputSource::USB;
    let debug_str = alloc::format!("{:?}", source);
    assert!(debug_str.contains("USB"));

    let source = InputSource::I2C;
    let debug_str = alloc::format!("{:?}", source);
    assert!(debug_str.contains("I2C"));
}

#[test]
fn test_input_manager_struct_creation() {
    let manager = InputManager::detect();
    let _source = manager.source();
}

#[test]
fn test_input_manager_source_returns_valid_source() {
    let manager = InputManager::detect();
    let source = manager.source();
    assert!(source == InputSource::PS2 || source == InputSource::USB || source == InputSource::I2C);
}

#[test]
fn test_input_source_all_variants() {
    let sources = [InputSource::PS2, InputSource::USB, InputSource::I2C];
    assert_eq!(sources.len(), 3);
}

#[test]
fn test_input_source_pattern_matching() {
    let source = InputSource::PS2;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    assert_eq!(result, "ps2");
}

#[test]
fn test_input_source_usb_pattern() {
    let source = InputSource::USB;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    assert_eq!(result, "usb");
}

#[test]
fn test_input_source_i2c_pattern() {
    let source = InputSource::I2C;
    let result = match source {
        InputSource::PS2 => "ps2",
        InputSource::USB => "usb",
        InputSource::I2C => "i2c",
    };
    assert_eq!(result, "i2c");
}
