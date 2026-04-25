// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::bus::*;
use crate::test::framework::TestResult;

pub(crate) fn test_pci_device_empty_creation() -> TestResult {
    let dev = PciDevice::empty();
    if dev.bus != 0 {
        return TestResult::Fail;
    }
    if dev.device != 0 {
        return TestResult::Fail;
    }
    if dev.function != 0 {
        return TestResult::Fail;
    }
    if dev.vendor_id != 0xFFFF {
        return TestResult::Fail;
    }
    if dev.device_id != 0xFFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_empty_is_invalid() -> TestResult {
    let dev = PciDevice::empty();
    if dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_with_valid_vendor_is_valid() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x8086;
    dev.device_id = 0x1234;
    if !dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_all_bars_initially_zero() -> TestResult {
    let dev = PciDevice::empty();
    if dev.bar0 != 0 {
        return TestResult::Fail;
    }
    if dev.bar1 != 0 {
        return TestResult::Fail;
    }
    if dev.bar2 != 0 {
        return TestResult::Fail;
    }
    if dev.bar3 != 0 {
        return TestResult::Fail;
    }
    if dev.bar4 != 0 {
        return TestResult::Fail;
    }
    if dev.bar5 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_irq_fields() -> TestResult {
    let dev = PciDevice::empty();
    if dev.irq_line != 0 {
        return TestResult::Fail;
    }
    if dev.irq_pin != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_fields() -> TestResult {
    let dev = PciDevice::empty();
    if dev.class != 0 {
        return TestResult::Fail;
    }
    if dev.subclass != 0 {
        return TestResult::Fail;
    }
    if dev.prog_if != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_header_type() -> TestResult {
    let dev = PciDevice::empty();
    if dev.header_type != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_vendor_id_ffff_invalid() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0xFFFF;
    dev.device_id = 0x0000;
    if dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_vendor_id_zero_is_valid() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x0000;
    dev.device_id = 0x1234;
    if !dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_copy_trait() -> TestResult {
    let dev1 = PciDevice::empty();
    let dev2 = dev1;
    if dev1.vendor_id != dev2.vendor_id {
        return TestResult::Fail;
    }
    if dev1.device_id != dev2.device_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_clone_trait() -> TestResult {
    let dev1 = PciDevice::empty();
    let dev2 = dev1.clone();
    if dev1.vendor_id != dev2.vendor_id {
        return TestResult::Fail;
    }
    if dev1.device_id != dev2.device_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_multifunction_header() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x80;
    if dev.header_type & 0x80 != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_standard_header() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x00;
    if dev.header_type & 0x7F != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_bridge_header() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x01;
    if dev.header_type & 0x7F != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_cardbus_header() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x02;
    if dev.header_type & 0x7F != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_storage() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.class = 0x01;
    dev.subclass = 0x08;
    if dev.class != 0x01 {
        return TestResult::Fail;
    }
    if dev.subclass != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_network() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.class = 0x02;
    dev.subclass = 0x00;
    if dev.class != 0x02 {
        return TestResult::Fail;
    }
    if dev.subclass != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_display() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.class = 0x03;
    dev.subclass = 0x00;
    if dev.class != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_class_serial_bus() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.class = 0x0C;
    dev.subclass = 0x03;
    dev.prog_if = 0x30;
    if dev.class != 0x0C {
        return TestResult::Fail;
    }
    if dev.subclass != 0x03 {
        return TestResult::Fail;
    }
    if dev.prog_if != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_bus_range() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.bus = 255;
    if dev.bus != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_device_range() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.device = 31;
    if dev.device != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_function_range() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.function = 7;
    if dev.function != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_intel_vendor() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x8086;
    if dev.vendor_id != 0x8086 {
        return TestResult::Fail;
    }
    if !dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_amd_vendor() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x1022;
    if dev.vendor_id != 0x1022 {
        return TestResult::Fail;
    }
    if !dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_virtio_vendor() -> TestResult {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x1AF4;
    if dev.vendor_id != 0x1AF4 {
        return TestResult::Fail;
    }
    if !dev.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
