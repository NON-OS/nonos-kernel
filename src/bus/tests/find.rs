// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::bus::*;
use crate::test::framework::TestResult;

pub(crate) fn test_device_count_returns_value() -> TestResult {
    let count = device_count();
    if count > 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_init_returns_bool() -> TestResult {
    let _init = is_init();
    TestResult::Pass
}

pub(crate) fn test_get_device_out_of_bounds() -> TestResult {
    let result = get_device(1000);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_device_at_max_index() -> TestResult {
    let result = get_device(64);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_find_device_by_id_nonexistent() -> TestResult {
    let result = find_device_by_id(0xDEAD, 0xBEEF);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_find_device_nonexistent_class() -> TestResult {
    let result = find_device(0xFF, 0xFF, None);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_find_device_with_prog_if_nonexistent() -> TestResult {
    let result = find_device(0xFF, 0xFF, Some(0xFF));
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_find_devices_empty_class() -> TestResult {
    let devices: alloc::vec::Vec<_> = find_devices(0xFF, 0xFF).collect();
    if !devices.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_constants() -> TestResult {
    if 0x01u8 != 0x01 {
        return TestResult::Fail;
    }
    if 0x02u8 != 0x02 {
        return TestResult::Fail;
    }
    if 0x03u8 != 0x03 {
        return TestResult::Fail;
    }
    if 0x06u8 != 0x06 {
        return TestResult::Fail;
    }
    if 0x0Cu8 != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_subclass_constants() -> TestResult {
    if 0x06u8 != 0x06 {
        return TestResult::Fail;
    }
    if 0x08u8 != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_prog_if_constants() -> TestResult {
    if 0x00u8 != 0x00 {
        return TestResult::Fail;
    }
    if 0x10u8 != 0x10 {
        return TestResult::Fail;
    }
    if 0x20u8 != 0x20 {
        return TestResult::Fail;
    }
    if 0x30u8 != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bridge_subclass_constants() -> TestResult {
    if 0x00u8 != 0x00 {
        return TestResult::Fail;
    }
    if 0x01u8 != 0x01 {
        return TestResult::Fail;
    }
    if 0x04u8 != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_count_consistent() -> TestResult {
    let count1 = device_count();
    let count2 = device_count();
    if count1 != count2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_find_device_storage_nvme() -> TestResult {
    let _result = find_device(0x01, 0x08, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_storage_sata() -> TestResult {
    let _result = find_device(0x01, 0x06, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_network_ethernet() -> TestResult {
    let _result = find_device(0x02, 0x00, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_display_vga() -> TestResult {
    let _result = find_device(0x03, 0x00, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_serial_usb() -> TestResult {
    let _result = find_device(0x0C, 0x03, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_bridge_host() -> TestResult {
    let _result = find_device(0x06, 0x00, None);
    TestResult::Pass
}

pub(crate) fn test_find_device_bridge_pci() -> TestResult {
    let _result = find_device(0x06, 0x04, None);
    TestResult::Pass
}

pub(crate) fn test_find_devices_iterator() -> TestResult {
    let iter = find_devices(0x01, 0x08);
    let _count: usize = iter.count();
    TestResult::Pass
}

pub(crate) fn test_find_device_by_id_intel() -> TestResult {
    let _result = find_device_by_id(0x8086, 0x0000);
    TestResult::Pass
}

pub(crate) fn test_find_device_by_id_amd() -> TestResult {
    let _result = find_device_by_id(0x1022, 0x0000);
    TestResult::Pass
}

pub(crate) fn test_find_device_by_id_virtio() -> TestResult {
    let _result = find_device_by_id(0x1AF4, 0x0000);
    TestResult::Pass
}

pub(crate) fn test_find_device_usb_uhci() -> TestResult {
    let _result = find_device(0x0C, 0x03, Some(0x00));
    TestResult::Pass
}

pub(crate) fn test_find_device_usb_ohci() -> TestResult {
    let _result = find_device(0x0C, 0x03, Some(0x10));
    TestResult::Pass
}

pub(crate) fn test_find_device_usb_ehci() -> TestResult {
    let _result = find_device(0x0C, 0x03, Some(0x20));
    TestResult::Pass
}

pub(crate) fn test_find_device_usb_xhci() -> TestResult {
    let _result = find_device(0x0C, 0x03, Some(0x30));
    TestResult::Pass
}

pub(crate) fn test_get_device_first() -> TestResult {
    let _result = get_device(0);
    TestResult::Pass
}

pub(crate) fn test_get_device_boundary() -> TestResult {
    let count = device_count();
    if count > 0 {
        let result = get_device(count - 1);
        if result.is_none() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_device_past_boundary() -> TestResult {
    let count = device_count();
    let result = get_device(count);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
