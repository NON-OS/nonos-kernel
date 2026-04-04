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

use crate::syscall::types::*;

#[test]
fn test_syscall_result_success() {
    let result = SyscallResult::success(42);
    assert_eq!(result.value, 42);
    assert!(!result.capability_consumed);
    assert!(!result.audit_required);
}

#[test]
fn test_syscall_result_success_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
    assert!(!result.is_error());
}

#[test]
fn test_syscall_result_success_max() {
    let result = SyscallResult::success(i64::MAX);
    assert_eq!(result.value, i64::MAX);
    assert!(!result.is_error());
}

#[test]
fn test_syscall_result_success_audited() {
    let result = SyscallResult::success_audited(100);
    assert_eq!(result.value, 100);
    assert!(!result.capability_consumed);
    assert!(result.audit_required);
}

#[test]
fn test_syscall_result_error() {
    let result = SyscallResult::error(22);
    assert!(result.is_error());
    assert_eq!(result.errno(), Some(22));
    assert!(result.audit_required);
}

#[test]
fn test_syscall_result_error_value_is_negated() {
    let result = SyscallResult::error(1);
    assert_eq!(result.value, -1);
}

#[test]
fn test_syscall_result_is_error_positive() {
    let result = SyscallResult::success(1);
    assert!(!result.is_error());
}

#[test]
fn test_syscall_result_is_error_zero() {
    let result = SyscallResult::success(0);
    assert!(!result.is_error());
}

#[test]
fn test_syscall_result_is_error_negative() {
    let result = SyscallResult::error(1);
    assert!(result.is_error());
}

#[test]
fn test_syscall_result_errno_none_for_success() {
    let result = SyscallResult::success(42);
    assert_eq!(result.errno(), None);
}

#[test]
fn test_syscall_result_errno_some_for_error() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_errno_helper() {
    let result = errno(errnos::EINVAL);
    assert!(result.is_error());
    assert_eq!(result.errno(), Some(errnos::EINVAL));
}

#[test]
fn test_errno_helper_eperm() {
    let result = errno(errnos::EPERM);
    assert_eq!(result.errno(), Some(1));
}

#[test]
fn test_errno_helper_enoent() {
    let result = errno(errnos::ENOENT);
    assert_eq!(result.errno(), Some(2));
}

#[test]
fn test_syscall_result_const_success() {
    const RESULT: SyscallResult = SyscallResult::success(99);
    assert_eq!(RESULT.value, 99);
}

#[test]
fn test_syscall_result_const_error() {
    const RESULT: SyscallResult = SyscallResult::error(22);
    assert_eq!(RESULT.value, -22);
}
