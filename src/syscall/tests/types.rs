// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Syscall result type tests

use crate::syscall::types::*;
use crate::test::framework::TestResult;

pub(crate) fn test_syscall_result_success() -> TestResult {
    let result = SyscallResult::success(42);
    if result.value != 42 {
        return TestResult::Fail;
    }
    if result.capability_consumed {
        return TestResult::Fail;
    }
    if result.audit_required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_success_zero() -> TestResult {
    let result = SyscallResult::success(0);
    if result.value != 0 {
        return TestResult::Fail;
    }
    if result.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_success_max() -> TestResult {
    let result = SyscallResult::success(i64::MAX);
    if result.value != i64::MAX {
        return TestResult::Fail;
    }
    if result.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_success_audited() -> TestResult {
    let result = SyscallResult::success_audited(100);
    if result.value != 100 {
        return TestResult::Fail;
    }
    if result.capability_consumed {
        return TestResult::Fail;
    }
    if !result.audit_required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_error() -> TestResult {
    let result = SyscallResult::error(22);
    if !result.is_error() {
        return TestResult::Fail;
    }
    if result.errno() != Some(22) {
        return TestResult::Fail;
    }
    if !result.audit_required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_error_value_is_negated() -> TestResult {
    let result = SyscallResult::error(1);
    if result.value != -1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_is_error_positive() -> TestResult {
    let result = SyscallResult::success(1);
    if result.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_is_error_zero() -> TestResult {
    let result = SyscallResult::success(0);
    if result.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_is_error_negative() -> TestResult {
    let result = SyscallResult::error(1);
    if !result.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_errno_none_for_success() -> TestResult {
    let result = SyscallResult::success(42);
    if result.errno() != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_errno_some_for_error() -> TestResult {
    let result = SyscallResult::error(22);
    if result.errno() != Some(22) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_helper() -> TestResult {
    let result = errno(errnos::EINVAL);
    if !result.is_error() {
        return TestResult::Fail;
    }
    if result.errno() != Some(errnos::EINVAL) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_helper_eperm() -> TestResult {
    let result = errno(errnos::EPERM);
    if result.errno() != Some(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_helper_enoent() -> TestResult {
    let result = errno(errnos::ENOENT);
    if result.errno() != Some(2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_const_success() -> TestResult {
    const RESULT: SyscallResult = SyscallResult::success(99);
    if RESULT.value != 99 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_result_const_error() -> TestResult {
    const RESULT: SyscallResult = SyscallResult::error(22);
    if RESULT.value != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
