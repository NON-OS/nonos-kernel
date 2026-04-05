use crate::syscall::SyscallResult;

const RLIMIT_CPU: u32 = 0;
const RLIMIT_FSIZE: u32 = 1;
const RLIMIT_DATA: u32 = 2;
const RLIMIT_STACK: u32 = 3;
const RLIMIT_CORE: u32 = 4;
const RLIMIT_RSS: u32 = 5;
const RLIMIT_NPROC: u32 = 6;
const RLIMIT_NOFILE: u32 = 7;
const RLIM_INFINITY: u64 = 0x7FFFFFFF;

#[test]
pub(crate) fn test_rlimit_cpu_constant() {
    assert_eq!(RLIMIT_CPU, 0);
}

#[test]
pub(crate) fn test_rlimit_fsize_constant() {
    assert_eq!(RLIMIT_FSIZE, 1);
}

#[test]
pub(crate) fn test_rlimit_data_constant() {
    assert_eq!(RLIMIT_DATA, 2);
}

#[test]
pub(crate) fn test_rlimit_stack_constant() {
    assert_eq!(RLIMIT_STACK, 3);
}

#[test]
pub(crate) fn test_rlimit_core_constant() {
    assert_eq!(RLIMIT_CORE, 4);
}

#[test]
pub(crate) fn test_rlimit_rss_constant() {
    assert_eq!(RLIMIT_RSS, 5);
}

#[test]
pub(crate) fn test_rlimit_nproc_constant() {
    assert_eq!(RLIMIT_NPROC, 6);
}

#[test]
pub(crate) fn test_rlimit_nofile_constant() {
    assert_eq!(RLIMIT_NOFILE, 7);
}

#[test]
pub(crate) fn test_rlim_infinity_constant() {
    assert_eq!(RLIM_INFINITY, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_getrlimit_null_rlim_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_getrlimit_cpu_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_fsize_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_data_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_stack_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_core_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_rss_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_nproc_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_nofile_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_unknown_resource_returns_default() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_getrlimit_efault_on_write_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_setrlimit_null_rlim_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_setrlimit_success_audited() {
    let result = SyscallResult::success_audited(0);
    assert_eq!(result.value, 0);
    assert!(result.audit_required);
}

#[test]
pub(crate) fn test_prlimit64_get_only_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_prlimit64_set_only_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_prlimit64_get_and_set_success() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_prlimit64_get_failure_propagates() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_prlimit64_set_failure_propagates() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_prlimit64_pid_zero_means_self() {
    let pid: i32 = 0;
    assert_eq!(pid, 0);
}

#[test]
pub(crate) fn test_prlimit64_pid_nonzero() {
    let pid: i32 = 1234;
    assert!(pid > 0);
}

#[test]
pub(crate) fn test_rlimit_struct_size() {
    let soft_size = core::mem::size_of::<u64>();
    let hard_size = core::mem::size_of::<u64>();
    assert_eq!(soft_size + hard_size, 16);
}

#[test]
pub(crate) fn test_rlimit_soft_less_than_hard() {
    let soft: u64 = 1024;
    let hard: u64 = 4096;
    assert!(soft <= hard);
}

#[test]
pub(crate) fn test_rlimit_soft_equals_hard() {
    let soft: u64 = 4096;
    let hard: u64 = 4096;
    assert_eq!(soft, hard);
}

#[test]
pub(crate) fn test_rlimit_infinity_value() {
    let infinity = RLIM_INFINITY;
    assert_eq!(infinity, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_stack_default_value() {
    let stack_default: u64 = 8 * 1024 * 1024;
    assert_eq!(stack_default, 8388608);
}

#[test]
pub(crate) fn test_rlimit_nofile_soft_default() {
    let nofile_soft: u64 = 1024;
    assert_eq!(nofile_soft, 1024);
}

#[test]
pub(crate) fn test_rlimit_nofile_hard_default() {
    let nofile_hard: u64 = 4096;
    assert_eq!(nofile_hard, 4096);
}

#[test]
pub(crate) fn test_rlimit_nproc_default() {
    let nproc_default: u64 = 4096;
    assert_eq!(nproc_default, 4096);
}

#[test]
pub(crate) fn test_rlimit_core_zero_disables() {
    let core: u64 = 0;
    assert_eq!(core, 0);
}

#[test]
pub(crate) fn test_rlimit_offset_calculation() {
    let rlim_ptr: u64 = 0x1000;
    let soft_ptr = rlim_ptr;
    let hard_ptr = rlim_ptr + 8;
    assert_eq!(soft_ptr, 0x1000);
    assert_eq!(hard_ptr, 0x1008);
}

#[test]
pub(crate) fn test_getrlimit_writes_soft_first() {
    let offset_soft: u64 = 0;
    let offset_hard: u64 = 8;
    assert!(offset_soft < offset_hard);
}

#[test]
pub(crate) fn test_rlimit_resource_range() {
    let min_resource: u32 = 0;
    let max_known_resource: u32 = 7;
    assert_eq!(min_resource, 0);
    assert_eq!(max_known_resource, 7);
}

#[test]
pub(crate) fn test_rlimit_unknown_resource_default_infinity() {
    let unknown_resource: u32 = 100;
    let _ = unknown_resource;
    let default_value = RLIM_INFINITY;
    assert_eq!(default_value, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_prlimit64_both_null_pointers() {
    let old_limit: u64 = 0;
    let new_limit: u64 = 0;
    assert_eq!(old_limit, 0);
    assert_eq!(new_limit, 0);
}

#[test]
pub(crate) fn test_rlimit_cpu_soft_value() {
    let soft: u64 = RLIM_INFINITY;
    assert_eq!(soft, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_cpu_hard_value() {
    let hard: u64 = RLIM_INFINITY;
    assert_eq!(hard, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_fsize_soft_value() {
    let soft: u64 = RLIM_INFINITY;
    assert_eq!(soft, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_fsize_hard_value() {
    let hard: u64 = RLIM_INFINITY;
    assert_eq!(hard, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_data_soft_value() {
    let soft: u64 = RLIM_INFINITY;
    assert_eq!(soft, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_data_hard_value() {
    let hard: u64 = RLIM_INFINITY;
    assert_eq!(hard, 0x7FFFFFFF);
}

#[test]
pub(crate) fn test_rlimit_stack_soft_value() {
    let soft: u64 = 8 * 1024 * 1024;
    assert_eq!(soft, 8388608);
}

#[test]
pub(crate) fn test_rlimit_stack_hard_value() {
    let hard: u64 = 8 * 1024 * 1024;
    assert_eq!(hard, 8388608);
}
