use crate::boot::multiboot::platform::{Platform, ConsoleType};

#[test]
fn platform_as_str_qemu() {
    assert_eq!(Platform::Qemu.as_str(), "QEMU");
}

#[test]
fn platform_as_str_vm() {
    assert_eq!(Platform::VirtualMachine.as_str(), "Virtual Machine");
}

#[test]
fn platform_as_str_baremetal() {
    assert_eq!(Platform::BareMetal.as_str(), "Bare Metal");
}

#[test]
fn platform_is_virtual_qemu() {
    assert!(Platform::Qemu.is_virtual());
}

#[test]
fn platform_is_virtual_vm() {
    assert!(Platform::VirtualMachine.is_virtual());
}

#[test]
fn platform_is_virtual_baremetal() {
    assert!(!Platform::BareMetal.is_virtual());
}

#[test]
fn platform_timer_frequency_qemu() {
    assert_eq!(Platform::Qemu.timer_frequency(), 1000);
}

#[test]
fn platform_timer_frequency_vm() {
    assert_eq!(Platform::VirtualMachine.timer_frequency(), 100);
}

#[test]
fn platform_timer_frequency_baremetal() {
    assert_eq!(Platform::BareMetal.timer_frequency(), 1000);
}

#[test]
fn platform_supports_virtio_qemu() {
    assert!(Platform::Qemu.supports_virtio());
}

#[test]
fn platform_supports_virtio_vm() {
    assert!(Platform::VirtualMachine.supports_virtio());
}

#[test]
fn platform_supports_virtio_baremetal() {
    assert!(!Platform::BareMetal.supports_virtio());
}

#[test]
fn platform_console_type_qemu() {
    assert_eq!(Platform::Qemu.console_type(), ConsoleType::Serial);
}

#[test]
fn platform_console_type_vm() {
    assert_eq!(Platform::VirtualMachine.console_type(), ConsoleType::Vga);
}

#[test]
fn platform_console_type_baremetal() {
    assert_eq!(Platform::BareMetal.console_type(), ConsoleType::Vga);
}

#[test]
fn platform_display() {
    use alloc::string::ToString;
    assert_eq!(Platform::Qemu.to_string(), "QEMU");
    assert_eq!(Platform::VirtualMachine.to_string(), "Virtual Machine");
    assert_eq!(Platform::BareMetal.to_string(), "Bare Metal");
}

#[test]
fn platform_equality() {
    assert_eq!(Platform::Qemu, Platform::Qemu);
    assert_eq!(Platform::VirtualMachine, Platform::VirtualMachine);
    assert_eq!(Platform::BareMetal, Platform::BareMetal);
    assert_ne!(Platform::Qemu, Platform::BareMetal);
}

#[test]
fn platform_clone() {
    let p = Platform::Qemu;
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn platform_copy() {
    let p = Platform::Qemu;
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn platform_debug() {
    use alloc::format;
    assert_eq!(format!("{:?}", Platform::Qemu), "Qemu");
    assert_eq!(format!("{:?}", Platform::VirtualMachine), "VirtualMachine");
    assert_eq!(format!("{:?}", Platform::BareMetal), "BareMetal");
}

#[test]
fn platform_hash() {
    use core::hash::{Hash, Hasher};
    use core::hash::BuildHasher;

    fn hash_platform<H: Hasher>(platform: Platform, hasher: &mut H) {
        platform.hash(hasher);
    }

    let p1 = Platform::Qemu;
    let p2 = Platform::Qemu;
    let p3 = Platform::BareMetal;

    let mut h1 = ahash::AHasher::default();
    let mut h2 = ahash::AHasher::default();
    let mut h3 = ahash::AHasher::default();

    hash_platform(p1, &mut h1);
    hash_platform(p2, &mut h2);
    hash_platform(p3, &mut h3);

    assert_eq!(h1.finish(), h2.finish());
    assert_ne!(h1.finish(), h3.finish());
}

#[test]
fn console_type_as_str_vga() {
    assert_eq!(ConsoleType::Vga.as_str(), "VGA");
}

#[test]
fn console_type_as_str_serial() {
    assert_eq!(ConsoleType::Serial.as_str(), "Serial");
}

#[test]
fn console_type_as_str_framebuffer() {
    assert_eq!(ConsoleType::Framebuffer.as_str(), "Framebuffer");
}

#[test]
fn console_type_display() {
    use alloc::string::ToString;
    assert_eq!(ConsoleType::Vga.to_string(), "VGA");
    assert_eq!(ConsoleType::Serial.to_string(), "Serial");
    assert_eq!(ConsoleType::Framebuffer.to_string(), "Framebuffer");
}

#[test]
fn console_type_equality() {
    assert_eq!(ConsoleType::Vga, ConsoleType::Vga);
    assert_eq!(ConsoleType::Serial, ConsoleType::Serial);
    assert_eq!(ConsoleType::Framebuffer, ConsoleType::Framebuffer);
    assert_ne!(ConsoleType::Vga, ConsoleType::Serial);
}

#[test]
fn console_type_clone() {
    let c = ConsoleType::Serial;
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn console_type_copy() {
    let c = ConsoleType::Serial;
    let c2 = c;
    assert_eq!(c, c2);
}

#[test]
fn console_type_debug() {
    use alloc::format;
    assert_eq!(format!("{:?}", ConsoleType::Vga), "Vga");
    assert_eq!(format!("{:?}", ConsoleType::Serial), "Serial");
    assert_eq!(format!("{:?}", ConsoleType::Framebuffer), "Framebuffer");
}
