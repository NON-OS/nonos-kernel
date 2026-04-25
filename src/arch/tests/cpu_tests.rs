// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::cpu::get_cpu_id;
use crate::test::framework::TestResult;

pub(crate) fn test_get_cpu_id_returns_valid() -> TestResult {
    let id = get_cpu_id();
    if id >= 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cpu_id_consistent() -> TestResult {
    let id1 = get_cpu_id();
    let id2 = get_cpu_id();
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_id_is_zero_on_bsp() -> TestResult {
    let id = get_cpu_id();
    if id != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
