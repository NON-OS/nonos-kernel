// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use core::mem::size_of;
use super::*;

#[test]
fn test_handoff_size() {
    assert!(size_of::<BootHandoffV1>() < 4096);
}

#[test]
fn test_default_valid() {
    let h = BootHandoffV1::default();
    assert!(h.is_valid());
    assert_eq!(h.magic, HANDOFF_MAGIC);
    assert_eq!(h.version, HANDOFF_VERSION);
}

#[test]
fn test_flags() {
    let mut h = BootHandoffV1::default();
    h.flags = flags::WX | flags::NXE | flags::SMEP;

    assert!(h.has_flag(flags::WX));
    assert!(h.has_flag(flags::NXE));
    assert!(h.has_flag(flags::SMEP));
    assert!(!h.has_flag(flags::SMAP));
    assert!(!h.has_flag(flags::FB_AVAILABLE));
}

#[test]
fn test_framebuffer_available() {
    let mut h = BootHandoffV1::default();

    assert!(h.framebuffer().is_none());

    h.flags = flags::FB_AVAILABLE;
    assert!(h.framebuffer().is_none());

    h.fb.ptr = 0xFD00_0000;
    assert!(h.framebuffer().is_some());
}

#[test]
fn test_acpi_available() {
    let mut h = BootHandoffV1::default();

    assert!(h.acpi_rsdp().is_none());

    h.flags = flags::ACPI_AVAILABLE;
    h.acpi.rsdp = 0xE0000;
    assert_eq!(h.acpi_rsdp(), Some(0xE0000));
}

#[test]
fn test_secure_boot() {
    let mut h = BootHandoffV1::default();

    assert!(!h.secure_boot_enabled());

    h.flags = flags::SECURE_BOOT;
    assert!(h.secure_boot_enabled());

    h.flags = 0;
    h.meas.secure_boot = 1;
    assert!(h.secure_boot_enabled());
}

#[test]
fn test_kernel_verified() {
    let mut h = BootHandoffV1::default();

    assert!(!h.kernel_verified());

    h.meas.kernel_sig_ok = 1;
    assert!(h.kernel_verified());
}

#[test]
fn test_memory_map_empty() {
    let mmap = MemoryMap::default();
    unsafe {
        assert!(mmap.entries().is_empty());
        assert_eq!(mmap.total_usable_memory(), 0);
    }
}

#[test]
fn test_modules_empty() {
    let modules = Modules::default();
    unsafe {
        assert!(modules.modules().is_empty());
    }
}

#[test]
fn test_framebuffer_info_valid() {
    let mut fb = FramebufferInfo::default();
    assert!(!fb.is_valid());

    fb.ptr = 0xFD00_0000;
    fb.width = 800;
    fb.height = 600;
    fb.stride = 3200;
    assert!(fb.is_valid());
}

#[test]
fn test_framebuffer_bytes_per_pixel() {
    let mut fb = FramebufferInfo::default();

    fb.pixel_format = pixel_format::RGB;
    assert_eq!(fb.bytes_per_pixel(), 3);

    fb.pixel_format = pixel_format::BGR;
    assert_eq!(fb.bytes_per_pixel(), 3);

    fb.pixel_format = pixel_format::RGBX;
    assert_eq!(fb.bytes_per_pixel(), 4);

    fb.pixel_format = pixel_format::BGRX;
    assert_eq!(fb.bytes_per_pixel(), 4);
}

#[test]
fn test_magic_value() {
    assert_eq!(HANDOFF_MAGIC, 0x4E_4F_4E_4F);
    assert_eq!((HANDOFF_MAGIC >> 24) as u8, b'O');
    assert_eq!(((HANDOFF_MAGIC >> 16) & 0xFF) as u8, b'N');
}
