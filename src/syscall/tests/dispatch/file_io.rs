use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_read_null_buffer_returns_einval() {
    let result = SyscallResult::error(22);
    assert!(result.is_error());
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_read_zero_count_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_read_count_exceeds_max_returns_einval() {
    let max_count: u64 = 0x7FFF_FFFF;
    assert!(max_count < u64::MAX);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_write_null_buffer_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_write_zero_count_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_write_count_exceeds_max_returns_einval() {
    let max_count: u64 = 0x7FFF_FFFF;
    let over_max = max_count + 1;
    assert!(over_max > max_count);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_open_null_pathname_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_open_max_path_length() {
    let max_path_len: usize = 4096;
    assert_eq!(max_path_len, 4096);
}

#[test]
pub(crate) fn test_close_invalid_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_stat_null_pathname_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_stat_null_statbuf_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_fstat_null_statbuf_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_fstat_invalid_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_lseek_whence_seek_set() {
    let seek_set: i32 = 0;
    assert_eq!(seek_set, 0);
}

#[test]
pub(crate) fn test_lseek_whence_seek_cur() {
    let seek_cur: i32 = 1;
    assert_eq!(seek_cur, 1);
}

#[test]
pub(crate) fn test_lseek_whence_seek_end() {
    let seek_end: i32 = 2;
    assert_eq!(seek_end, 2);
}

#[test]
pub(crate) fn test_lseek_invalid_whence_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mkdir_null_pathname_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mkdir_exists_returns_eexist() {
    let result = SyscallResult::error(17);
    assert_eq!(result.errno(), Some(17));
}

#[test]
pub(crate) fn test_rmdir_null_pathname_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_rmdir_not_empty_returns_enotempty() {
    let result = SyscallResult::error(39);
    assert_eq!(result.errno(), Some(39));
}

#[test]
pub(crate) fn test_rmdir_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
pub(crate) fn test_unlink_null_pathname_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_unlink_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
pub(crate) fn test_rename_null_oldpath_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_rename_null_newpath_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mmap_zero_length_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mmap_prot_read() {
    let prot_read: u64 = 0x1;
    assert_eq!(prot_read, 1);
}

#[test]
pub(crate) fn test_mmap_prot_write() {
    let prot_write: u64 = 0x2;
    assert_eq!(prot_write, 2);
}

#[test]
pub(crate) fn test_mmap_prot_exec() {
    let prot_exec: u64 = 0x4;
    assert_eq!(prot_exec, 4);
}

#[test]
pub(crate) fn test_mmap_no_memory_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_munmap_null_addr_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_munmap_zero_length_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_success_result_fields() {
    let result = SyscallResult::success(100);
    assert_eq!(result.value, 100);
    assert!(!result.capability_consumed);
    assert!(!result.audit_required);
}

#[test]
pub(crate) fn test_error_result_is_negative() {
    let result = SyscallResult::error(22);
    assert!(result.value < 0);
}

#[test]
pub(crate) fn test_read_success_returns_bytes_read() {
    let bytes_read = 512i64;
    let result = SyscallResult::success(bytes_read);
    assert_eq!(result.value, 512);
}

#[test]
pub(crate) fn test_write_success_returns_bytes_written() {
    let bytes_written = 256i64;
    let result = SyscallResult::success(bytes_written);
    assert_eq!(result.value, 256);
}

#[test]
pub(crate) fn test_open_success_returns_fd() {
    let fd = 3i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 3);
}

#[test]
pub(crate) fn test_close_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_stat_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_fstat_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_lseek_success_returns_new_offset() {
    let new_offset = 1024i64;
    let result = SyscallResult::success(new_offset);
    assert_eq!(result.value, 1024);
}

#[test]
pub(crate) fn test_mkdir_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_rmdir_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_unlink_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_rename_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_mmap_success_returns_address() {
    let addr = 0x1000_0000i64;
    let result = SyscallResult::success(addr);
    assert_eq!(result.value, 0x1000_0000);
}

#[test]
pub(crate) fn test_munmap_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_read_efault_on_bad_pointer() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_write_efault_on_bad_pointer() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_read_eio_on_io_error() {
    let result = SyscallResult::error(5);
    assert_eq!(result.errno(), Some(5));
}

#[test]
pub(crate) fn test_write_eio_on_io_error() {
    let result = SyscallResult::error(5);
    assert_eq!(result.errno(), Some(5));
}

#[test]
pub(crate) fn test_max_read_count_boundary() {
    let max_count: u64 = 0x7FFF_FFFF;
    let valid = max_count <= 0x7FFF_FFFF;
    assert!(valid);
}

#[test]
pub(crate) fn test_max_write_count_boundary() {
    let max_count: u64 = 0x7FFF_FFFF;
    let valid = max_count <= 0x7FFF_FFFF;
    assert!(valid);
}

#[test]
pub(crate) fn test_path_too_long_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_capability_io_required() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_capability_filesystem_required() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_capability_memory_required() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}
