// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;
#[test]
fn test_reexports_available() {
    let _ = HANDOFF_MAGIC;
    let _ = HANDOFF_VERSION;
    let _ = flags::WX;
    let _ = pixel_format::RGB;
    let _ = memory_type::CONVENTIONAL;
}

#[test]
fn test_handoff_constants() {
    assert_eq!(HANDOFF_MAGIC, 0x4E_4F_4E_4F);
    assert_eq!(HANDOFF_VERSION, 1);
}

#[test]
fn test_memory_types() {
    assert_eq!(memory_type::RESERVED, 0);
    assert_eq!(memory_type::LOADER_CODE, 1);
    assert_eq!(memory_type::LOADER_DATA, 2);
    assert_eq!(memory_type::CONVENTIONAL, 7);
    assert_eq!(memory_type::ACPI_RECLAIM, 9);
    assert_eq!(memory_type::ACPI_NVS, 10);
}

#[test]
fn test_pixel_formats() {
    assert_eq!(pixel_format::RGB, 0);
    assert_eq!(pixel_format::BGR, 1);
    assert_eq!(pixel_format::RGBX, 2);
    assert_eq!(pixel_format::BGRX, 3);
}

#[test]
fn test_flags() {
    assert_eq!(flags::WX, 1 << 0);
    assert_eq!(flags::NXE, 1 << 1);
    assert_eq!(flags::SMEP, 1 << 2);
    assert_eq!(flags::SMAP, 1 << 3);
    assert_eq!(flags::UMIP, 1 << 4);
    assert_eq!(flags::IDMAP_PRESERVED, 1 << 5);
    assert_eq!(flags::FB_AVAILABLE, 1 << 6);
    assert_eq!(flags::ACPI_AVAILABLE, 1 << 7);
    assert_eq!(flags::TPM_MEASURED, 1 << 8);
    assert_eq!(flags::SECURE_BOOT, 1 << 9);
}
