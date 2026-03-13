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

use crate::loader::*;

#[test]
fn test_kernel_image_builder() {
    let image = image::KernelImageBuilder::new()
        .address(0x100000)
        .size(0x50000)
        .entry_point(0x101000)
        .build();

    assert_eq!(image.address, 0x100000);
    assert_eq!(image.size, 0x50000);
    assert_eq!(image.entry_point, 0x101000);
    assert!(image.is_entry_valid());
}

#[test]
fn test_kernel_image_contains() {
    let image = image::KernelImageBuilder::new()
        .address(0x100000)
        .size(0x10000)
        .entry_point(0x100000)
        .build();

    assert!(image.contains(0x100000));
    assert!(image.contains(0x10FFFF));
    assert!(!image.contains(0x110000));
}
