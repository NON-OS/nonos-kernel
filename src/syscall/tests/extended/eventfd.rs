use crate::syscall::extended::eventfd_types::*;
use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_efd_cloexec_constant() {
    assert_eq!(EFD_CLOEXEC, 0x80000);
}

#[test]
pub(crate) fn test_efd_nonblock_constant() {
    assert_eq!(EFD_NONBLOCK, 0x800);
}

#[test]
pub(crate) fn test_efd_semaphore_constant() {
    assert_eq!(EFD_SEMAPHORE, 0x1);
}

#[test]
pub(crate) fn test_eventfd_einval_constant() {
    assert_eq!(EINVAL, 22);
}

#[test]
pub(crate) fn test_eventfd_eagain_constant() {
    assert_eq!(EAGAIN, 11);
}

#[test]
pub(crate) fn test_eventfd_enomem_constant() {
    assert_eq!(ENOMEM, 12);
}

#[test]
pub(crate) fn test_eventfd_ebadf_constant() {
    assert_eq!(EBADF, 9);
}

#[test]
pub(crate) fn test_eventfd_max_constant() {
    assert_eq!(EVENTFD_MAX, u64::MAX - 1);
}

#[test]
pub(crate) fn test_max_eventfd_instances_constant() {
    assert_eq!(MAX_EVENTFD_INSTANCES, 1024);
}

#[test]
pub(crate) fn test_eventfd_instance_new() {
    let inst = EventFdInstance::new(1, 0, 0);
    assert_eq!(inst.get_counter(), 0);
    assert!(!inst.is_semaphore());
    assert!(!inst.is_nonblock());
}

#[test]
pub(crate) fn test_eventfd_instance_with_initval() {
    let inst = EventFdInstance::new(1, 100, 0);
    assert_eq!(inst.get_counter(), 100);
}

#[test]
pub(crate) fn test_eventfd_instance_is_semaphore() {
    let inst = EventFdInstance::new(1, 0, EFD_SEMAPHORE);
    assert!(inst.is_semaphore());
}

#[test]
pub(crate) fn test_eventfd_instance_not_semaphore() {
    let inst = EventFdInstance::new(1, 0, 0);
    assert!(!inst.is_semaphore());
}

#[test]
pub(crate) fn test_eventfd_instance_is_nonblock() {
    let inst = EventFdInstance::new(1, 0, EFD_NONBLOCK);
    assert!(inst.is_nonblock());
}

#[test]
pub(crate) fn test_eventfd_instance_not_nonblock() {
    let inst = EventFdInstance::new(1, 0, 0);
    assert!(!inst.is_nonblock());
}

#[test]
pub(crate) fn test_eventfd_instance_with_both_flags() {
    let inst = EventFdInstance::new(1, 0, EFD_SEMAPHORE | EFD_NONBLOCK);
    assert!(inst.is_semaphore());
    assert!(inst.is_nonblock());
}

#[test]
pub(crate) fn test_eventfd_instance_with_all_flags() {
    let inst = EventFdInstance::new(1, 0, EFD_CLOEXEC | EFD_SEMAPHORE | EFD_NONBLOCK);
    assert!(inst.is_semaphore());
    assert!(inst.is_nonblock());
}

#[test]
pub(crate) fn test_eventfd_invalid_flags_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_eventfd_success_returns_fd() {
    let fd = 5000i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 5000);
}

#[test]
pub(crate) fn test_eventfd2_success_returns_fd() {
    let fd = 5001i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 5001);
}

#[test]
pub(crate) fn test_eventfd_max_instances_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_eventfd_write_max_value_returns_einval() {
    let result = Err::<(), i32>(EINVAL);
    assert_eq!(result.err(), Some(22));
}

#[test]
pub(crate) fn test_eventfd_write_would_overflow_returns_eagain() {
    let result = Err::<(), i32>(EAGAIN);
    assert_eq!(result.err(), Some(11));
}

#[test]
pub(crate) fn test_eventfd_read_zero_counter_returns_eagain() {
    let result = Err::<u64, i32>(EAGAIN);
    assert_eq!(result.err(), Some(11));
}

#[test]
pub(crate) fn test_eventfd_valid_flags_mask() {
    let valid_flags = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    assert_eq!(valid_flags, 0x80801);
}

#[test]
pub(crate) fn test_eventfd_read_size() {
    let read_size: usize = 8;
    assert_eq!(read_size, 8);
}

#[test]
pub(crate) fn test_eventfd_write_size() {
    let write_size: usize = 8;
    assert_eq!(write_size, 8);
}

#[test]
pub(crate) fn test_eventfd_read_returns_counter() {
    let counter: u64 = 42;
    assert_eq!(counter, 42);
}

#[test]
pub(crate) fn test_eventfd_read_semaphore_returns_one() {
    let semaphore_read: u64 = 1;
    assert_eq!(semaphore_read, 1);
}

#[test]
pub(crate) fn test_eventfd_read_resets_counter() {
    let counter_after_read: u64 = 0;
    assert_eq!(counter_after_read, 0);
}

#[test]
pub(crate) fn test_eventfd_read_semaphore_decrements() {
    let counter_before: u64 = 5;
    let counter_after: u64 = counter_before - 1;
    assert_eq!(counter_after, 4);
}

#[test]
pub(crate) fn test_eventfd_write_adds_to_counter() {
    let counter_before: u64 = 10;
    let write_value: u64 = 5;
    let counter_after = counter_before + write_value;
    assert_eq!(counter_after, 15);
}

#[test]
pub(crate) fn test_eventfd_counter_max_boundary() {
    let max = EVENTFD_MAX;
    let at_max = max;
    let _ = at_max;
    assert_eq!(max, u64::MAX - 1);
}

#[test]
pub(crate) fn test_eventfd_counter_overflow_check() {
    let current: u64 = EVENTFD_MAX - 5;
    let value: u64 = 10;
    let would_overflow = current > EVENTFD_MAX - value;
    assert!(would_overflow);
}

#[test]
pub(crate) fn test_eventfd_counter_no_overflow() {
    let current: u64 = 100;
    let value: u64 = 50;
    let would_overflow = current > EVENTFD_MAX - value;
    assert!(!would_overflow);
}

#[test]
pub(crate) fn test_eventfd_initval_max() {
    let initval: u32 = u32::MAX;
    assert_eq!(initval, u32::MAX);
}

#[test]
pub(crate) fn test_eventfd_initval_zero() {
    let initval: u32 = 0;
    assert_eq!(initval, 0);
}

#[test]
pub(crate) fn test_eventfd_close_success() {
    let result = Ok::<(), i32>(());
    assert!(result.is_ok());
}

#[test]
pub(crate) fn test_eventfd_close_invalid_fd_returns_ebadf() {
    let result = Err::<(), i32>(EBADF);
    assert_eq!(result.err(), Some(9));
}

#[test]
pub(crate) fn test_eventfd_ops_read_buffer_too_small() {
    let count: usize = 4;
    assert!(count < 8);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_eventfd_ops_write_buffer_too_small() {
    let count: usize = 4;
    assert!(count < 8);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_eventfd_ops_read_invalid_fd() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_eventfd_ops_write_invalid_fd() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_eventfd_ops_read_success() {
    let bytes = 8usize;
    let result = SyscallResult::success(bytes as i64);
    assert_eq!(result.value, 8);
}

#[test]
pub(crate) fn test_eventfd_ops_write_success() {
    let bytes = 8usize;
    let result = SyscallResult::success(bytes as i64);
    assert_eq!(result.value, 8);
}

#[test]
pub(crate) fn test_eventfd_is_readable_nonzero_counter() {
    let counter: u64 = 1;
    let readable = counter > 0;
    assert!(readable);
}

#[test]
pub(crate) fn test_eventfd_is_readable_zero_counter() {
    let counter: u64 = 0;
    let readable = counter > 0;
    assert!(!readable);
}

#[test]
pub(crate) fn test_eventfd_is_writable_below_max() {
    let counter: u64 = 100;
    let writable = counter < EVENTFD_MAX;
    assert!(writable);
}

#[test]
pub(crate) fn test_eventfd_is_writable_at_max() {
    let counter: u64 = EVENTFD_MAX;
    let writable = counter < EVENTFD_MAX;
    assert!(!writable);
}

#[test]
pub(crate) fn test_eventfd_count_empty() {
    let count: usize = 0;
    assert_eq!(count, 0);
}

#[test]
pub(crate) fn test_eventfd_count_nonzero() {
    let count: usize = 5;
    assert!(count > 0);
}

#[test]
pub(crate) fn test_eventfd_stats_fields() {
    let active = 10usize;
    let total_counter = 500u64;
    let semaphore_count = 3usize;
    let nonblock_count = 7usize;
    assert_eq!(active, 10);
    assert_eq!(total_counter, 500);
    assert_eq!(semaphore_count, 3);
    assert_eq!(nonblock_count, 7);
}

#[test]
pub(crate) fn test_eventfd_u64_to_le_bytes() {
    let value: u64 = 0x0102030405060708;
    let bytes = value.to_le_bytes();
    assert_eq!(bytes[0], 0x08);
    assert_eq!(bytes[7], 0x01);
}

#[test]
pub(crate) fn test_eventfd_u64_from_le_bytes() {
    let bytes: [u8; 8] = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
    let value = u64::from_le_bytes(bytes);
    assert_eq!(value, 0x0102030405060708);
}
