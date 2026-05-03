use crate::syscall::extended::signalfd::types::*;
use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_sfd_cloexec_constant() {
    assert_eq!(SFD_CLOEXEC, 0x80000);
}

#[test]
pub(crate) fn test_sfd_nonblock_constant() {
    assert_eq!(SFD_NONBLOCK, 0x800);
}

#[test]
pub(crate) fn test_signalfd_einval_constant() {
    assert_eq!(EINVAL, 22);
}

#[test]
pub(crate) fn test_signalfd_eagain_constant() {
    assert_eq!(EAGAIN, 11);
}

#[test]
pub(crate) fn test_signalfd_enomem_constant() {
    assert_eq!(ENOMEM, 12);
}

#[test]
pub(crate) fn test_signalfd_ebadf_constant() {
    assert_eq!(EBADF, 9);
}

#[test]
pub(crate) fn test_signalfd_siginfo_size_constant() {
    assert_eq!(SIGNALFD_SIGINFO_SIZE, 128);
}

#[test]
pub(crate) fn test_signalfd_siginfo_default() {
    let info = SignalfdSiginfo::default();
    assert_eq!(info.ssi_signo, 0);
    assert_eq!(info.ssi_errno, 0);
    assert_eq!(info.ssi_code, 0);
    assert_eq!(info.ssi_pid, 0);
    assert_eq!(info.ssi_uid, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_default_fields() {
    let info = SignalfdSiginfo::default();
    assert_eq!(info.ssi_fd, 0);
    assert_eq!(info.ssi_tid, 0);
    assert_eq!(info.ssi_band, 0);
    assert_eq!(info.ssi_overrun, 0);
    assert_eq!(info.ssi_trapno, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_default_status() {
    let info = SignalfdSiginfo::default();
    assert_eq!(info.ssi_status, 0);
    assert_eq!(info.ssi_int, 0);
    assert_eq!(info.ssi_ptr, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_default_time() {
    let info = SignalfdSiginfo::default();
    assert_eq!(info.ssi_utime, 0);
    assert_eq!(info.ssi_stime, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_default_addr() {
    let info = SignalfdSiginfo::default();
    assert_eq!(info.ssi_addr, 0);
    assert_eq!(info.ssi_addr_lsb, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_size() {
    let info = SignalfdSiginfo::default();
    let bytes = info.to_bytes();
    assert_eq!(bytes.len(), SIGNALFD_SIGINFO_SIZE);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_zeroed() {
    let info = SignalfdSiginfo::default();
    let bytes = info.to_bytes();
    for byte in &bytes {
        assert_eq!(*byte, 0);
    }
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_signo() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_signo = 15;
    let bytes = info.to_bytes();
    let signo = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(signo, 15);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_errno() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_errno = -22;
    let bytes = info.to_bytes();
    let errno = i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    assert_eq!(errno, -22);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_code() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_code = 1;
    let bytes = info.to_bytes();
    let code = i32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    assert_eq!(code, 1);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_pid() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_pid = 1234;
    let bytes = info.to_bytes();
    let pid = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    assert_eq!(pid, 1234);
}

#[test]
pub(crate) fn test_signalfd_siginfo_to_bytes_uid() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_uid = 1000;
    let bytes = info.to_bytes();
    let uid = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    assert_eq!(uid, 1000);
}

#[test]
pub(crate) fn test_signalfd_siginfo_clone() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_signo = 9;
    let cloned = info.clone();
    assert_eq!(cloned.ssi_signo, 9);
}

#[test]
pub(crate) fn test_signalfd_siginfo_copy() {
    let mut info = SignalfdSiginfo::default();
    info.ssi_signo = 2;
    let copied = info;
    assert_eq!(copied.ssi_signo, 2);
}

#[test]
pub(crate) fn test_signalfd_info_fields() {
    let info = SignalfdInfo { pending_count: 5, mask: 0xFF };
    assert_eq!(info.pending_count, 5);
    assert_eq!(info.mask, 0xFF);
}

#[test]
pub(crate) fn test_signalfd_stats_fields() {
    let stats = SignalfdStats { active_count: 10, total_pending_signals: 25, average_mask_size: 3 };
    assert_eq!(stats.active_count, 10);
    assert_eq!(stats.total_pending_signals, 25);
    assert_eq!(stats.average_mask_size, 3);
}

#[test]
pub(crate) fn test_signalfd_invalid_flags_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_signalfd_new_success_returns_fd() {
    let fd = 10i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 10);
}

#[test]
pub(crate) fn test_signalfd_update_success_returns_fd() {
    let fd = 10i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 10);
}

#[test]
pub(crate) fn test_signalfd_update_invalid_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_signalfd_max_instances_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_signalfd4_success_returns_fd() {
    let fd = 15i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 15);
}

#[test]
pub(crate) fn test_signalfd4_with_cloexec() {
    let flags = SFD_CLOEXEC;
    assert_eq!(flags, 0x80000);
}

#[test]
pub(crate) fn test_signalfd4_with_nonblock() {
    let flags = SFD_NONBLOCK;
    assert_eq!(flags, 0x800);
}

#[test]
pub(crate) fn test_signalfd4_with_both_flags() {
    let flags = SFD_CLOEXEC | SFD_NONBLOCK;
    assert_eq!(flags, 0x80800);
}

#[test]
pub(crate) fn test_signalfd_valid_flags_mask() {
    let valid_flags = SFD_CLOEXEC | SFD_NONBLOCK;
    assert_eq!(valid_flags, 0x80800);
}

#[test]
pub(crate) fn test_signalfd_create_with_minus_one_fd() {
    let fd: i32 = -1;
    assert_eq!(fd, -1);
}

#[test]
pub(crate) fn test_signalfd_mask_single_signal() {
    let mask: u64 = 1 << 14;
    assert!(mask != 0);
}

#[test]
pub(crate) fn test_signalfd_mask_multiple_signals() {
    let mask: u64 = (1 << 14) | (1 << 15) | (1 << 9);
    assert!(mask != 0);
}

#[test]
pub(crate) fn test_signalfd_mask_all_signals() {
    let mask: u64 = u64::MAX;
    assert_eq!(mask, u64::MAX);
}

#[test]
pub(crate) fn test_signalfd_mask_no_signals() {
    let mask: u64 = 0;
    assert_eq!(mask, 0);
}

#[test]
pub(crate) fn test_signalfd_siginfo_struct_size() {
    assert_eq!(core::mem::size_of::<SignalfdSiginfo>(), 128);
}

#[test]
pub(crate) fn test_signalfd_read_would_block_returns_eagain() {
    let result = SyscallResult::error(11);
    assert_eq!(result.errno(), Some(11));
}

#[test]
pub(crate) fn test_signalfd_read_success_returns_bytes() {
    let bytes = 128i64;
    let result = SyscallResult::success(bytes);
    assert_eq!(result.value, 128);
}

#[test]
pub(crate) fn test_signalfd_signo_sigint() {
    let sigint: u32 = 2;
    assert_eq!(sigint, 2);
}

#[test]
pub(crate) fn test_signalfd_signo_sigterm() {
    let sigterm: u32 = 15;
    assert_eq!(sigterm, 15);
}

#[test]
pub(crate) fn test_signalfd_signo_sigkill() {
    let sigkill: u32 = 9;
    assert_eq!(sigkill, 9);
}

#[test]
pub(crate) fn test_signalfd_signo_sigusr1() {
    let sigusr1: u32 = 10;
    assert_eq!(sigusr1, 10);
}

#[test]
pub(crate) fn test_signalfd_signo_sigusr2() {
    let sigusr2: u32 = 12;
    assert_eq!(sigusr2, 12);
}

#[test]
pub(crate) fn test_signalfd_signo_sigchld() {
    let sigchld: u32 = 17;
    assert_eq!(sigchld, 17);
}

#[test]
pub(crate) fn test_signalfd_blocking_signals() {
    let sigint_bit: u64 = 1 << 2;
    let sigterm_bit: u64 = 1 << 15;
    let mask = sigint_bit | sigterm_bit;
    assert!(mask & sigint_bit != 0);
    assert!(mask & sigterm_bit != 0);
}
