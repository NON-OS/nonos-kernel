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

use super::types::SelfTestResult;
use super::core::{ct_compare, ct_select_u8, ct_select_u32, ct_swap_slices};
use super::ops::{ct_lt_u32, ct_eq_u32, ct_min_u32, ct_max_u32};
use super::memory::{ct_zero, ct_hmac_verify};

pub fn run_self_tests() -> SelfTestResult {
    let mut tests_run = 0u32;
    let mut tests_passed = 0u32;

    tests_run += 1;
    let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let b = [1u8, 2, 3, 4, 5, 6, 7, 8];
    if ct_compare(&a, &b) {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_compare: equal arrays reported as different"),
        };
    }

    tests_run += 1;
    let c = [1u8, 2, 3, 4, 5, 6, 7, 9];
    if !ct_compare(&a, &c) {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_compare: different arrays reported as equal"),
        };
    }

    tests_run += 1;
    let d = [1u8, 2, 3, 4];
    if !ct_compare(&a, &d) {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_compare: different lengths reported as equal"),
        };
    }

    tests_run += 1;
    if ct_select_u8(1, 0xAA, 0xBB) == 0xAA && ct_select_u8(0, 0xAA, 0xBB) == 0xBB {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_select_u8: incorrect selection"),
        };
    }

    tests_run += 1;
    if ct_select_u32(1, 0xDEADBEEF, 0xCAFEBABE) == 0xDEADBEEF
        && ct_select_u32(0, 0xDEADBEEF, 0xCAFEBABE) == 0xCAFEBABE {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_select_u32: incorrect selection"),
        };
    }

    tests_run += 1;
    if ct_lt_u32(5, 10) == 1 && ct_lt_u32(10, 5) == 0 && ct_lt_u32(5, 5) == 0 {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_lt_u32: incorrect comparison"),
        };
    }

    tests_run += 1;
    if ct_eq_u32(42, 42) == 1 && ct_eq_u32(42, 43) == 0 {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_eq_u32: incorrect equality check"),
        };
    }

    tests_run += 1;
    let mut x = [1u8, 2, 3, 4];
    let mut y = [5u8, 6, 7, 8];
    ct_swap_slices(1, &mut x, &mut y);
    if x == [5, 6, 7, 8] && y == [1, 2, 3, 4] {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_swap_slices: incorrect swap"),
        };
    }

    tests_run += 1;
    ct_swap_slices(0, &mut x, &mut y);
    if x == [5, 6, 7, 8] && y == [1, 2, 3, 4] {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_swap_slices: swapped when condition was 0"),
        };
    }

    tests_run += 1;
    let mut z = [0xFFu8; 16];
    ct_zero(&mut z);
    if z == [0u8; 16] {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_zero: failed to zero memory"),
        };
    }

    tests_run += 1;
    let hmac_a = [0xABu8; 32];
    let hmac_b = [0xABu8; 32];
    let hmac_c = [0xCDu8; 32];
    if ct_hmac_verify(&hmac_a, &hmac_b) && !ct_hmac_verify(&hmac_a, &hmac_c) {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_hmac_verify: incorrect result"),
        };
    }

    tests_run += 1;
    if ct_min_u32(100, 200) == 100 && ct_max_u32(100, 200) == 200 {
        tests_passed += 1;
    } else {
        return SelfTestResult {
            passed: false,
            tests_run,
            tests_passed,
            failure_description: Some("ct_min/ct_max: incorrect result"),
        };
    }

    SelfTestResult {
        passed: tests_passed == tests_run,
        tests_run,
        tests_passed,
        failure_description: None,
    }
}
