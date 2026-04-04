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

use crate::bus::*;

#[test]
fn test_get_bar_address_zero_returns_none() {
    let result = get_bar_address(0);
    assert!(result.is_none());
}

#[test]
fn test_get_bar_address_io_space_bit() {
    let bar = 0x1001;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0x1000);
}

#[test]
fn test_get_bar_address_io_space_mask() {
    let bar = 0xFFFF_FFFD;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xFFFF_FFFC);
}

#[test]
fn test_get_bar_address_memory_32bit_type0() {
    let bar = 0xF000_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xF000_0000);
}

#[test]
fn test_get_bar_address_memory_32bit_mask() {
    let bar: u32 = 0xF000_0008;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xF000_0000);
}

#[test]
fn test_get_bar_address_memory_type2_below_4g() {
    let bar = 0xF000_0004;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xF000_0000);
}

#[test]
fn test_get_bar_address_memory_type1_reserved() {
    let bar = 0xF000_0002;
    let result = get_bar_address(bar);
    assert!(result.is_none());
}

#[test]
fn test_get_bar_address_memory_type3_reserved() {
    let bar = 0xF000_0006;
    let result = get_bar_address(bar);
    assert!(result.is_none());
}

#[test]
fn test_get_bar_address_io_space_typical() {
    let bar = 0x0000_C001;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xC000);
}

#[test]
fn test_get_bar_address_io_space_low_port() {
    let bar = 0x0000_0101;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0x0100);
}

#[test]
fn test_get_bar_address_memory_prefetchable() {
    let bar = 0xF000_0008;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xF000_0000);
}

#[test]
fn test_get_bar_address_memory_non_prefetchable() {
    let bar = 0xF000_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xF000_0000);
}

#[test]
fn test_get_bar_address_all_ones_io() {
    let bar = 0xFFFF_FFFF;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xFFFF_FFFC);
}

#[test]
fn test_get_bar_address_typical_mmio() {
    let bar = 0xFEB0_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xFEB0_0000);
}

#[test]
fn test_get_bar_address_typical_vga() {
    let bar = 0xE000_0008;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0xE000_0000);
}

#[test]
fn test_bar_io_bit_extraction() {
    let io_bar = 0x1001;
    assert_eq!(io_bar & 0x01, 1);

    let mem_bar = 0x1000;
    assert_eq!(mem_bar & 0x01, 0);
}

#[test]
fn test_bar_type_extraction() {
    let type0: u32 = 0xF000_0000;
    assert_eq!((type0 >> 1) & 0x03, 0);

    let type1: u32 = 0xF000_0002;
    assert_eq!((type1 >> 1) & 0x03, 1);

    let type2: u32 = 0xF000_0004;
    assert_eq!((type2 >> 1) & 0x03, 2);

    let type3: u32 = 0xF000_0006;
    assert_eq!((type3 >> 1) & 0x03, 3);
}

#[test]
fn test_bar_prefetchable_extraction() {
    let prefetchable: u32 = 0xF000_0008;
    assert_eq!((prefetchable >> 3) & 0x01, 1);

    let non_prefetchable: u32 = 0xF000_0000;
    assert_eq!((non_prefetchable >> 3) & 0x01, 0);
}

#[test]
fn test_command_register_bus_master_bit() {
    let bus_master_bit = 0x04;
    assert_eq!(bus_master_bit, 1 << 2);
}

#[test]
fn test_command_register_memory_space_bit() {
    let memory_space_bit = 0x02;
    assert_eq!(memory_space_bit, 1 << 1);
}

#[test]
fn test_command_register_io_space_bit() {
    let io_space_bit = 0x01;
    assert_eq!(io_space_bit, 1 << 0);
}

#[test]
fn test_get_bar_address_edge_case_one() {
    let bar = 0x0000_0001;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_get_bar_address_edge_case_two() {
    let bar = 0x0000_0002;
    let result = get_bar_address(bar);
    assert!(result.is_none());
}

#[test]
fn test_get_bar_address_small_memory() {
    let bar = 0x0001_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0x0001_0000);
}

#[test]
fn test_get_bar_address_page_aligned() {
    let bar = 0x0010_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0x0010_0000);
}

#[test]
fn test_get_bar_address_megabyte_aligned() {
    let bar = 0x0100_0000;
    let result = get_bar_address(bar);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0x0100_0000);
}
