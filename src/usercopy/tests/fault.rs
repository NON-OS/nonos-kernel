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

use crate::test::framework::TestResult;
use crate::usercopy::*;

pub(crate) fn test_set_fault_handler_returns_guard() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    TestResult::Pass
}

pub(crate) fn test_clear_fault_handler_no_panic() -> TestResult {
    clear_fault_handler();
    TestResult::Pass
}

pub(crate) fn test_try_recover_fault_without_handler() -> TestResult {
    clear_fault_handler();
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_try_recover_fault_with_handler() -> TestResult {
    let _guard = set_fault_handler(0xDEAD_BEEF);
    let result = try_recover_fault();
    if !result.is_some() {
        return TestResult::Fail;
    }
    if result != Some(0xDEAD_BEEF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_initially_false() -> TestResult {
    clear_fault_handler();
    let _guard = set_fault_handler(0x1000);
    if did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_after_try_recover() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    let _ = try_recover_fault();
    if !did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_recovery_guard_clears_handler() -> TestResult {
    {
        let _guard = set_fault_handler(0x1000);
        let result = try_recover_fault();
        if !result.is_some() {
            return TestResult::Fail;
        }
    }
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_recovery_rip_zero() -> TestResult {
    let _guard = set_fault_handler(0);
    let result = try_recover_fault();
    if result != Some(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_recovery_rip_max() -> TestResult {
    let _guard = set_fault_handler(u64::MAX);
    let result = try_recover_fault();
    if result != Some(u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_typical_address() -> TestResult {
    let _guard = set_fault_handler(0xFFFF_FFFF_8000_0000);
    let result = try_recover_fault();
    if result != Some(0xFFFF_FFFF_8000_0000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_set_fault_handler_overwrites() -> TestResult {
    let _guard1 = set_fault_handler(0x1000);
    let _guard2 = set_fault_handler(0x2000);
    let result = try_recover_fault();
    if result != Some(0x2000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clear_fault_handler_multiple_times() -> TestResult {
    clear_fault_handler();
    clear_fault_handler();
    clear_fault_handler();
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_false_without_handler() -> TestResult {
    clear_fault_handler();
    if did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_try_recover_fault_idempotent() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    let result1 = try_recover_fault();
    let result2 = try_recover_fault();
    if result1 != result2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_after_multiple_try_recover() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    let _ = try_recover_fault();
    let _ = try_recover_fault();
    let _ = try_recover_fault();
    if !did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_recovery_guard_drop_order() -> TestResult {
    let _guard1 = set_fault_handler(0x1000);
    {
        let _guard2 = set_fault_handler(0x2000);
    }
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_page_aligned() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    let result = try_recover_fault();
    if result != Some(0x1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_non_page_aligned() -> TestResult {
    let _guard = set_fault_handler(0x1001);
    let result = try_recover_fault();
    if result != Some(0x1001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_recovery_guard_size() -> TestResult {
    let guard = set_fault_handler(0x1000);
    if !(core::mem::size_of_val(&guard) > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clear_then_set_fault_handler() -> TestResult {
    clear_fault_handler();
    let _guard = set_fault_handler(0x3000);
    let result = try_recover_fault();
    if result != Some(0x3000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_try_recover_after_guard_drop() -> TestResult {
    {
        let _guard = set_fault_handler(0x1000);
    }
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_resets_with_new_handler() -> TestResult {
    {
        let _guard = set_fault_handler(0x1000);
        let _ = try_recover_fault();
        if !did_fault() {
            return TestResult::Fail;
        }
    }
    let _guard = set_fault_handler(0x2000);
    if did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_with_kernel_address() -> TestResult {
    let _guard = set_fault_handler(0xFFFF_8000_0000_0000);
    let result = try_recover_fault();
    if result != Some(0xFFFF_8000_0000_0000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_with_user_address() -> TestResult {
    let _guard = set_fault_handler(0x0000_7FFF_FFFF_F000);
    let result = try_recover_fault();
    if result != Some(0x0000_7FFF_FFFF_F000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_fault_handler_sequence() -> TestResult {
    for i in 0..10 {
        let _guard = set_fault_handler(i * 0x1000);
        let result = try_recover_fault();
        if result != Some(i * 0x1000) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_clear_fault_handler_sequence() -> TestResult {
    for _ in 0..10 {
        clear_fault_handler();
        let result = try_recover_fault();
        if !result.is_none() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_fault_recovery_rip_preserved() -> TestResult {
    let _guard = set_fault_handler(0xABCD_EF01_2345_6789);
    let result = try_recover_fault();
    if result.unwrap() != 0xABCD_EF01_2345_6789 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_without_try_recover() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    if did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nested_fault_handler_inner_drop() -> TestResult {
    let _outer = set_fault_handler(0x1000);
    {
        let _inner = set_fault_handler(0x2000);
        let result = try_recover_fault();
        if result != Some(0x2000) {
            return TestResult::Fail;
        }
    }
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_boundary_values() -> TestResult {
    let values = [0u64, 1, u64::MAX - 1, u64::MAX, 0x8000_0000_0000_0000];
    for &val in &values {
        let _guard = set_fault_handler(val);
        let result = try_recover_fault();
        if result != Some(val) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_did_fault_consistency() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    if did_fault() {
        return TestResult::Fail;
    }
    let _ = try_recover_fault();
    if !did_fault() {
        return TestResult::Fail;
    }
    if !did_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clear_fault_handler_after_fault() -> TestResult {
    let _guard = set_fault_handler(0x1000);
    let _ = try_recover_fault();
    if !did_fault() {
        return TestResult::Fail;
    }
    clear_fault_handler();
    let result = try_recover_fault();
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_power_of_two_addresses() -> TestResult {
    for i in 0..48 {
        let addr = 1u64 << i;
        let _guard = set_fault_handler(addr);
        let result = try_recover_fault();
        if result != Some(addr) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_alternating_bits() -> TestResult {
    let _guard = set_fault_handler(0x5555_5555_5555_5555);
    let result = try_recover_fault();
    if result != Some(0x5555_5555_5555_5555) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fault_handler_all_ones() -> TestResult {
    let _guard = set_fault_handler(0xFFFF_FFFF_FFFF_FFFF);
    let result = try_recover_fault();
    if result != Some(0xFFFF_FFFF_FFFF_FFFF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
