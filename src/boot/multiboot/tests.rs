use super::*;

#[test]
fn test_reexports_available() {
    let _ = memory_type::AVAILABLE;
    let _ = memory_type::RESERVED;
}

#[test]
fn test_memory_types() {
    assert_eq!(memory_type::AVAILABLE, 1);
    assert_eq!(memory_type::RESERVED, 2);
    assert_eq!(memory_type::ACPI_RECLAIMABLE, 3);
    assert_eq!(memory_type::ACPI_NVS, 4);
    assert_eq!(memory_type::BAD_MEMORY, 5);
}

#[test]
fn test_platform_enum() {
    let qemu = Platform::Qemu;
    let vm = Platform::VirtualMachine;
    let bare = Platform::BareMetal;
    assert_ne!(core::mem::discriminant(&qemu), core::mem::discriminant(&vm));
    assert_ne!(core::mem::discriminant(&vm), core::mem::discriminant(&bare));
    assert_ne!(core::mem::discriminant(&qemu), core::mem::discriminant(&bare));
}

#[test]
fn test_console_type_enum() {
    let vga = ConsoleType::Vga;
    let fb = ConsoleType::Framebuffer;
    let serial = ConsoleType::Serial;
    assert_ne!(core::mem::discriminant(&vga), core::mem::discriminant(&fb));
    assert_ne!(core::mem::discriminant(&fb), core::mem::discriminant(&serial));
}
