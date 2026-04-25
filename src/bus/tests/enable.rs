// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::bus::*;
use crate::test::framework::TestResult;

pub(crate) fn test_get_bar_address_zero_returns_none() -> TestResult {
    let result = get_bar_address(0);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_io_space_bit() -> TestResult {
    let bar = 0x1001;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_io_space_mask() -> TestResult {
    let bar = 0xFFFF_FFFD;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xFFFF_FFFC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_32bit_type0() -> TestResult {
    let bar = 0xF000_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xF000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_32bit_mask() -> TestResult {
    let bar: u32 = 0xF000_0008;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xF000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_type2_below_4g() -> TestResult {
    let bar = 0xF000_0004;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xF000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_type1_reserved() -> TestResult {
    let bar = 0xF000_0002;
    let result = get_bar_address(bar);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_type3_reserved() -> TestResult {
    let bar = 0xF000_0006;
    let result = get_bar_address(bar);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_io_space_typical() -> TestResult {
    let bar = 0x0000_C001;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xC000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_io_space_low_port() -> TestResult {
    let bar = 0x0000_0101;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0x0100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_prefetchable() -> TestResult {
    let bar = 0xF000_0008;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xF000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_memory_non_prefetchable() -> TestResult {
    let bar = 0xF000_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xF000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_all_ones_io() -> TestResult {
    let bar = 0xFFFF_FFFF;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xFFFF_FFFC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_typical_mmio() -> TestResult {
    let bar = 0xFEB0_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xFEB0_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_typical_vga() -> TestResult {
    let bar = 0xE000_0008;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0xE000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bar_io_bit_extraction() -> TestResult {
    let io_bar = 0x1001;
    if io_bar & 0x01 != 1 {
        return TestResult::Fail;
    }
    let mem_bar = 0x1000;
    if mem_bar & 0x01 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bar_type_extraction() -> TestResult {
    let type0: u32 = 0xF000_0000;
    if (type0 >> 1) & 0x03 != 0 {
        return TestResult::Fail;
    }
    let type1: u32 = 0xF000_0002;
    if (type1 >> 1) & 0x03 != 1 {
        return TestResult::Fail;
    }
    let type2: u32 = 0xF000_0004;
    if (type2 >> 1) & 0x03 != 2 {
        return TestResult::Fail;
    }
    let type3: u32 = 0xF000_0006;
    if (type3 >> 1) & 0x03 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bar_prefetchable_extraction() -> TestResult {
    let prefetchable: u32 = 0xF000_0008;
    if (prefetchable >> 3) & 0x01 != 1 {
        return TestResult::Fail;
    }
    let non_prefetchable: u32 = 0xF000_0000;
    if (non_prefetchable >> 3) & 0x01 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_register_bus_master_bit() -> TestResult {
    let bus_master_bit = 0x04;
    if bus_master_bit != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_register_memory_space_bit() -> TestResult {
    let memory_space_bit = 0x02;
    if memory_space_bit != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_register_io_space_bit() -> TestResult {
    let io_space_bit = 0x01;
    if io_space_bit != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_edge_case_one() -> TestResult {
    let bar = 0x0000_0001;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_edge_case_two() -> TestResult {
    let bar = 0x0000_0002;
    let result = get_bar_address(bar);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_small_memory() -> TestResult {
    let bar = 0x0001_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0x0001_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_page_aligned() -> TestResult {
    let bar = 0x0010_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0x0010_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_bar_address_megabyte_aligned() -> TestResult {
    let bar = 0x0100_0000;
    let result = get_bar_address(bar);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0x0100_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
