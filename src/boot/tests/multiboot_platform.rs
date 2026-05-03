// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::boot::multiboot::platform::{ConsoleType, Platform};
use crate::test::framework::TestResult;

pub(crate) fn test_platform_as_str_qemu() -> TestResult {
    if Platform::Qemu.as_str() != "QEMU" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_as_str_vm() -> TestResult {
    if Platform::VirtualMachine.as_str() != "Virtual Machine" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_as_str_baremetal() -> TestResult {
    if Platform::BareMetal.as_str() != "Bare Metal" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_is_virtual_qemu() -> TestResult {
    if !Platform::Qemu.is_virtual() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_is_virtual_vm() -> TestResult {
    if !Platform::VirtualMachine.is_virtual() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_is_virtual_baremetal() -> TestResult {
    if Platform::BareMetal.is_virtual() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_timer_frequency_qemu() -> TestResult {
    if Platform::Qemu.timer_frequency() != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_timer_frequency_vm() -> TestResult {
    if Platform::VirtualMachine.timer_frequency() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_timer_frequency_baremetal() -> TestResult {
    if Platform::BareMetal.timer_frequency() != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_supports_virtio_qemu() -> TestResult {
    if !Platform::Qemu.supports_virtio() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_supports_virtio_vm() -> TestResult {
    if !Platform::VirtualMachine.supports_virtio() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_supports_virtio_baremetal() -> TestResult {
    if Platform::BareMetal.supports_virtio() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_console_type_qemu() -> TestResult {
    if Platform::Qemu.console_type() != ConsoleType::Serial {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_console_type_vm() -> TestResult {
    if Platform::VirtualMachine.console_type() != ConsoleType::Vga {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_console_type_baremetal() -> TestResult {
    if Platform::BareMetal.console_type() != ConsoleType::Vga {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_equality() -> TestResult {
    if Platform::Qemu != Platform::Qemu {
        return TestResult::Fail;
    }
    if Platform::VirtualMachine != Platform::VirtualMachine {
        return TestResult::Fail;
    }
    if Platform::BareMetal != Platform::BareMetal {
        return TestResult::Fail;
    }
    if Platform::Qemu == Platform::BareMetal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_clone() -> TestResult {
    let p = Platform::Qemu;
    let p2 = p.clone();
    if p != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_platform_copy() -> TestResult {
    let p = Platform::Qemu;
    let p2 = p;
    if p != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_as_str_vga() -> TestResult {
    if ConsoleType::Vga.as_str() != "VGA" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_as_str_serial() -> TestResult {
    if ConsoleType::Serial.as_str() != "Serial" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_as_str_framebuffer() -> TestResult {
    if ConsoleType::Framebuffer.as_str() != "Framebuffer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_equality() -> TestResult {
    if ConsoleType::Vga != ConsoleType::Vga {
        return TestResult::Fail;
    }
    if ConsoleType::Serial != ConsoleType::Serial {
        return TestResult::Fail;
    }
    if ConsoleType::Framebuffer != ConsoleType::Framebuffer {
        return TestResult::Fail;
    }
    if ConsoleType::Vga == ConsoleType::Serial {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_clone() -> TestResult {
    let c = ConsoleType::Serial;
    let c2 = c.clone();
    if c != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_type_copy() -> TestResult {
    let c = ConsoleType::Serial;
    let c2 = c;
    if c != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
