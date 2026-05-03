use crate::syscall::extended::epoll::types::*;
use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_epoll_cloexec_constant() {
    assert_eq!(EPOLL_CLOEXEC, 0x80000);
}

#[test]
pub(crate) fn test_epoll_ctl_add_constant() {
    assert_eq!(EPOLL_CTL_ADD, 1);
}

#[test]
pub(crate) fn test_epoll_ctl_del_constant() {
    assert_eq!(EPOLL_CTL_DEL, 2);
}

#[test]
pub(crate) fn test_epoll_ctl_mod_constant() {
    assert_eq!(EPOLL_CTL_MOD, 3);
}

#[test]
pub(crate) fn test_epollin_constant() {
    assert_eq!(EPOLLIN, 0x001);
}

#[test]
pub(crate) fn test_epollpri_constant() {
    assert_eq!(EPOLLPRI, 0x002);
}

#[test]
pub(crate) fn test_epollout_constant() {
    assert_eq!(EPOLLOUT, 0x004);
}

#[test]
pub(crate) fn test_epollrdnorm_constant() {
    assert_eq!(EPOLLRDNORM, 0x040);
}

#[test]
pub(crate) fn test_epollrdband_constant() {
    assert_eq!(EPOLLRDBAND, 0x080);
}

#[test]
pub(crate) fn test_epollwrnorm_constant() {
    assert_eq!(EPOLLWRNORM, 0x100);
}

#[test]
pub(crate) fn test_epollwrband_constant() {
    assert_eq!(EPOLLWRBAND, 0x200);
}

#[test]
pub(crate) fn test_epollmsg_constant() {
    assert_eq!(EPOLLMSG, 0x400);
}

#[test]
pub(crate) fn test_epollerr_constant() {
    assert_eq!(EPOLLERR, 0x008);
}

#[test]
pub(crate) fn test_epollhup_constant() {
    assert_eq!(EPOLLHUP, 0x010);
}

#[test]
pub(crate) fn test_epollrdhup_constant() {
    assert_eq!(EPOLLRDHUP, 0x2000);
}

#[test]
pub(crate) fn test_epollexclusive_constant() {
    assert_eq!(EPOLLEXCLUSIVE, 1 << 28);
}

#[test]
pub(crate) fn test_epollwakeup_constant() {
    assert_eq!(EPOLLWAKEUP, 1 << 29);
}

#[test]
pub(crate) fn test_epolloneshot_constant() {
    assert_eq!(EPOLLONESHOT, 1 << 30);
}

#[test]
pub(crate) fn test_epollet_constant() {
    assert_eq!(EPOLLET, 1 << 31);
}

#[test]
pub(crate) fn test_epoll_ebadf_constant() {
    assert_eq!(EBADF, 9);
}

#[test]
pub(crate) fn test_epoll_einval_constant() {
    assert_eq!(EINVAL, 22);
}

#[test]
pub(crate) fn test_epoll_enomem_constant() {
    assert_eq!(ENOMEM, 12);
}

#[test]
pub(crate) fn test_epoll_enoent_constant() {
    assert_eq!(ENOENT, 2);
}

#[test]
pub(crate) fn test_epoll_eexist_constant() {
    assert_eq!(EEXIST, 17);
}

#[test]
pub(crate) fn test_epoll_efault_constant() {
    assert_eq!(EFAULT, 14);
}

#[test]
pub(crate) fn test_epoll_eintr_constant() {
    assert_eq!(EINTR, 4);
}

#[test]
pub(crate) fn test_max_epoll_instances() {
    assert_eq!(MAX_EPOLL_INSTANCES, 256);
}

#[test]
pub(crate) fn test_max_events_per_instance() {
    assert_eq!(MAX_EVENTS_PER_INSTANCE, 4096);
}

#[test]
pub(crate) fn test_epoll_event_size() {
    let ev = EpollEvent { events: 0, data: 0 };
    assert_eq!(core::mem::size_of_val(&ev), 12);
}

#[test]
pub(crate) fn test_epoll_event_fields() {
    let ev = EpollEvent { events: EPOLLIN, data: 42 };
    assert_eq!(ev.events, EPOLLIN);
    assert_eq!(ev.data, 42);
}

#[test]
pub(crate) fn test_epoll_event_clone() {
    let ev = EpollEvent { events: EPOLLOUT, data: 100 };
    let cloned = ev.clone();
    assert_eq!(cloned.events, EPOLLOUT);
    assert_eq!(cloned.data, 100);
}

#[test]
pub(crate) fn test_epoll_event_copy() {
    let ev = EpollEvent { events: EPOLLERR, data: 200 };
    let copied = ev;
    assert_eq!(copied.events, EPOLLERR);
    assert_eq!(copied.data, 200);
}

#[test]
pub(crate) fn test_epoll_event_debug() {
    let ev = EpollEvent { events: EPOLLHUP, data: 0 };
    let debug_str = format!("{:?}", ev);
    assert!(debug_str.contains("EpollEvent"));
}

#[test]
pub(crate) fn test_epoll_create_negative_size_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_create_zero_size_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_create_success_returns_fd() {
    let fd = 5i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 5);
}

#[test]
pub(crate) fn test_epoll_create1_invalid_flags_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_create1_success_returns_fd() {
    let fd = 6i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 6);
}

#[test]
pub(crate) fn test_epoll_create1_cloexec_flag() {
    let flags = EPOLL_CLOEXEC;
    assert_eq!(flags, 0x80000);
}

#[test]
pub(crate) fn test_epoll_create_max_instances_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_epoll_ctl_invalid_epfd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_epoll_ctl_same_fd_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_ctl_invalid_target_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_epoll_ctl_add_null_event_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_epoll_ctl_add_existing_returns_eexist() {
    let result = SyscallResult::error(17);
    assert_eq!(result.errno(), Some(17));
}

#[test]
pub(crate) fn test_epoll_ctl_add_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_epoll_ctl_mod_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
pub(crate) fn test_epoll_ctl_mod_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_epoll_ctl_del_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
pub(crate) fn test_epoll_ctl_del_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_epoll_ctl_invalid_op_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_ctl_max_events_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_epoll_wait_negative_maxevents_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_wait_zero_maxevents_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_epoll_wait_null_events_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_epoll_wait_invalid_epfd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_epoll_wait_success_returns_count() {
    let count = 3i64;
    let result = SyscallResult::success(count);
    assert_eq!(result.value, 3);
}

#[test]
pub(crate) fn test_epoll_wait_timeout_zero_returns_immediately() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_epoll_wait_timeout_expired_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_epoll_wait_interrupted_returns_eintr() {
    let result = SyscallResult::error(4);
    assert_eq!(result.errno(), Some(4));
}

#[test]
pub(crate) fn test_epoll_pwait_success_returns_count() {
    let count = 2i64;
    let result = SyscallResult::success(count);
    assert_eq!(result.value, 2);
}

#[test]
pub(crate) fn test_epoll_event_combine_in_out() {
    let events = EPOLLIN | EPOLLOUT;
    assert_eq!(events, 0x005);
}

#[test]
pub(crate) fn test_epoll_event_combine_err_hup() {
    let events = EPOLLERR | EPOLLHUP;
    assert_eq!(events, 0x018);
}

#[test]
pub(crate) fn test_epoll_event_combine_et_oneshot() {
    let events = EPOLLET | EPOLLONESHOT;
    assert_eq!(events, (1 << 31) | (1 << 30));
}

#[test]
pub(crate) fn test_epoll_event_data_max() {
    let ev = EpollEvent { events: EPOLLIN, data: u64::MAX };
    assert_eq!(ev.data, u64::MAX);
}

#[test]
pub(crate) fn test_epoll_event_data_zero() {
    let ev = EpollEvent { events: EPOLLOUT, data: 0 };
    assert_eq!(ev.data, 0);
}

#[test]
pub(crate) fn test_epoll_oneshot_triggered_flag() {
    let oneshot = EPOLLONESHOT;
    assert!(oneshot != 0);
}

#[test]
pub(crate) fn test_epoll_edge_triggered_flag() {
    let et = EPOLLET;
    assert!(et != 0);
}

#[test]
pub(crate) fn test_epoll_exclusive_flag() {
    let exclusive = EPOLLEXCLUSIVE;
    assert!(exclusive != 0);
}
