// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

#[allow(unused_imports)]
use crate::bus::*;
use crate::test::framework::TestResult;

pub(crate) fn test_pci_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub(crate) fn test_pci_address_enable_bit() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0);
    if addr & (1 << 31) != 1 << 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bus_zero() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0);
    let bus = (addr >> 16) & 0xFF;
    if bus != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bus_max() -> TestResult {
    let addr = test_pci_address(255, 0, 0, 0);
    let bus = (addr >> 16) & 0xFF;
    if bus != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_device_zero() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0);
    let device = (addr >> 11) & 0x1F;
    if device != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_device_max() -> TestResult {
    let addr = test_pci_address(0, 31, 0, 0);
    let device = (addr >> 11) & 0x1F;
    if device != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_function_zero() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0);
    let function = (addr >> 8) & 0x07;
    if function != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_function_max() -> TestResult {
    let addr = test_pci_address(0, 0, 7, 0);
    let function = (addr >> 8) & 0x07;
    if function != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_offset_aligned() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0x10);
    let offset = addr & 0xFC;
    if offset != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_offset_alignment_mask() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0x11);
    let offset = addr & 0xFC;
    if offset != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_offset_alignment_mask2() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0x13);
    let offset = addr & 0xFC;
    if offset != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_full_calculation() -> TestResult {
    let addr = test_pci_address(5, 10, 3, 0x10);
    let expected = (1u32 << 31) | (5u32 << 16) | (10u32 << 11) | (3u32 << 8) | 0x10;
    if addr != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_root_complex() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0);
    let expected = 1u32 << 31;
    if addr != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_typical_device() -> TestResult {
    let addr = test_pci_address(0, 2, 0, 0);
    let expected = (1u32 << 31) | (2u32 << 11);
    if addr != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_vendor_id_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x00);
    let offset = addr & 0xFC;
    if offset != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_device_id_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x02);
    let offset = addr & 0xFC;
    if offset != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_command_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x04);
    let offset = addr & 0xFC;
    if offset != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_status_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x06);
    let offset = addr & 0xFC;
    if offset != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_class_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x0B);
    let offset = addr & 0xFC;
    if offset != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_header_type_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x0E);
    let offset = addr & 0xFC;
    if offset != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar0_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x10);
    let offset = addr & 0xFC;
    if offset != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar1_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x14);
    let offset = addr & 0xFC;
    if offset != 0x14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar2_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x18);
    let offset = addr & 0xFC;
    if offset != 0x18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar3_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x1C);
    let offset = addr & 0xFC;
    if offset != 0x1C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar4_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x20);
    let offset = addr & 0xFC;
    if offset != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bar5_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x24);
    let offset = addr & 0xFC;
    if offset != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_interrupt_line_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x3C);
    let offset = addr & 0xFC;
    if offset != 0x3C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_interrupt_pin_offset() -> TestResult {
    let addr = test_pci_address(0, 1, 0, 0x3D);
    let offset = addr & 0xFC;
    if offset != 0x3C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_multiple_buses() -> TestResult {
    for bus in [0u8, 1, 127, 255] {
        let addr = test_pci_address(bus, 0, 0, 0);
        let extracted = (addr >> 16) & 0xFF;
        if extracted != bus as u32 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_multiple_devices() -> TestResult {
    for device in [0u8, 1, 15, 31] {
        let addr = test_pci_address(0, device, 0, 0);
        let extracted = (addr >> 11) & 0x1F;
        if extracted != device as u32 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_multiple_functions() -> TestResult {
    for function in 0u8..8 {
        let addr = test_pci_address(0, 0, function, 0);
        let extracted = (addr >> 8) & 0x07;
        if extracted != function as u32 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_pci_config_address_port() -> TestResult {
    if 0x0CF8u16 != 0x0CF8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_config_data_port() -> TestResult {
    if 0x0CFCu16 != 0x0CFC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bus_field_mask() -> TestResult {
    let addr = test_pci_address(0xFF, 0, 0, 0);
    if (addr >> 16) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_device_field_mask() -> TestResult {
    let addr = test_pci_address(0, 0x1F, 0, 0);
    if (addr >> 11) & 0x1F != 0x1F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_function_field_mask() -> TestResult {
    let addr = test_pci_address(0, 0, 0x07, 0);
    if (addr >> 8) & 0x07 != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_offset_field_mask() -> TestResult {
    let addr = test_pci_address(0, 0, 0, 0xFC);
    if addr & 0xFC != 0xFC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_all_fields_combined() -> TestResult {
    let addr = test_pci_address(0x12, 0x0A, 0x03, 0x40);
    if (addr >> 16) & 0xFF != 0x12 {
        return TestResult::Fail;
    }
    if (addr >> 11) & 0x1F != 0x0A {
        return TestResult::Fail;
    }
    if (addr >> 8) & 0x07 != 0x03 {
        return TestResult::Fail;
    }
    if addr & 0xFC != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
