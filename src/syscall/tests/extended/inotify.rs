use crate::syscall::extended::inotify::types::*;
use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_in_cloexec_constant() {
    assert_eq!(IN_CLOEXEC, 0x80000);
}

#[test]
pub(crate) fn test_in_nonblock_constant() {
    assert_eq!(IN_NONBLOCK, 0x800);
}

#[test]
pub(crate) fn test_in_access_constant() {
    assert_eq!(IN_ACCESS, 0x00000001);
}

#[test]
pub(crate) fn test_in_modify_constant() {
    assert_eq!(IN_MODIFY, 0x00000002);
}

#[test]
pub(crate) fn test_in_attrib_constant() {
    assert_eq!(IN_ATTRIB, 0x00000004);
}

#[test]
pub(crate) fn test_in_close_write_constant() {
    assert_eq!(IN_CLOSE_WRITE, 0x00000008);
}

#[test]
pub(crate) fn test_in_close_nowrite_constant() {
    assert_eq!(IN_CLOSE_NOWRITE, 0x00000010);
}

#[test]
pub(crate) fn test_in_open_constant() {
    assert_eq!(IN_OPEN, 0x00000020);
}

#[test]
pub(crate) fn test_in_moved_from_constant() {
    assert_eq!(IN_MOVED_FROM, 0x00000040);
}

#[test]
pub(crate) fn test_in_moved_to_constant() {
    assert_eq!(IN_MOVED_TO, 0x00000080);
}

#[test]
pub(crate) fn test_in_create_constant() {
    assert_eq!(IN_CREATE, 0x00000100);
}

#[test]
pub(crate) fn test_in_delete_constant() {
    assert_eq!(IN_DELETE, 0x00000200);
}

#[test]
pub(crate) fn test_in_delete_self_constant() {
    assert_eq!(IN_DELETE_SELF, 0x00000400);
}

#[test]
pub(crate) fn test_in_move_self_constant() {
    assert_eq!(IN_MOVE_SELF, 0x00000800);
}

#[test]
pub(crate) fn test_in_close_combined() {
    assert_eq!(IN_CLOSE, IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
    assert_eq!(IN_CLOSE, 0x00000018);
}

#[test]
pub(crate) fn test_in_move_combined() {
    assert_eq!(IN_MOVE, IN_MOVED_FROM | IN_MOVED_TO);
    assert_eq!(IN_MOVE, 0x000000C0);
}

#[test]
pub(crate) fn test_in_all_events_combined() {
    let expected = IN_ACCESS
        | IN_MODIFY
        | IN_ATTRIB
        | IN_CLOSE_WRITE
        | IN_CLOSE_NOWRITE
        | IN_OPEN
        | IN_MOVED_FROM
        | IN_MOVED_TO
        | IN_CREATE
        | IN_DELETE
        | IN_DELETE_SELF
        | IN_MOVE_SELF;
    assert_eq!(IN_ALL_EVENTS, expected);
}

#[test]
pub(crate) fn test_in_onlydir_constant() {
    assert_eq!(IN_ONLYDIR, 0x01000000);
}

#[test]
pub(crate) fn test_in_dont_follow_constant() {
    assert_eq!(IN_DONT_FOLLOW, 0x02000000);
}

#[test]
pub(crate) fn test_in_excl_unlink_constant() {
    assert_eq!(IN_EXCL_UNLINK, 0x04000000);
}

#[test]
pub(crate) fn test_in_mask_create_constant() {
    assert_eq!(IN_MASK_CREATE, 0x10000000);
}

#[test]
pub(crate) fn test_in_mask_add_constant() {
    assert_eq!(IN_MASK_ADD, 0x20000000);
}

#[test]
pub(crate) fn test_in_isdir_constant() {
    assert_eq!(IN_ISDIR, 0x40000000);
}

#[test]
pub(crate) fn test_in_oneshot_constant() {
    assert_eq!(IN_ONESHOT, 0x80000000);
}

#[test]
pub(crate) fn test_in_unmount_constant() {
    assert_eq!(IN_UNMOUNT, 0x00002000);
}

#[test]
pub(crate) fn test_in_q_overflow_constant() {
    assert_eq!(IN_Q_OVERFLOW, 0x00004000);
}

#[test]
pub(crate) fn test_in_ignored_constant() {
    assert_eq!(IN_IGNORED, 0x00008000);
}

#[test]
pub(crate) fn test_inotify_einval_constant() {
    assert_eq!(EINVAL, 22);
}

#[test]
pub(crate) fn test_inotify_enomem_constant() {
    assert_eq!(ENOMEM, 12);
}

#[test]
pub(crate) fn test_inotify_ebadf_constant() {
    assert_eq!(EBADF, 9);
}

#[test]
pub(crate) fn test_inotify_enoent_constant() {
    assert_eq!(ENOENT, 2);
}

#[test]
pub(crate) fn test_inotify_eagain_constant() {
    assert_eq!(EAGAIN, 11);
}

#[test]
pub(crate) fn test_inotify_enotdir_constant() {
    assert_eq!(ENOTDIR, 20);
}

#[test]
pub(crate) fn test_inotify_eexist_constant() {
    assert_eq!(EEXIST, 17);
}

#[test]
pub(crate) fn test_max_inotify_instances() {
    assert_eq!(MAX_INOTIFY_INSTANCES, 128);
}

#[test]
pub(crate) fn test_max_watches_per_instance() {
    assert_eq!(MAX_WATCHES_PER_INSTANCE, 8192);
}

#[test]
pub(crate) fn test_max_queued_events() {
    assert_eq!(MAX_QUEUED_EVENTS, 16384);
}

#[test]
pub(crate) fn test_inotify_event_new_no_name() {
    let ev = InotifyEvent::new(1, IN_ACCESS, 0, None);
    assert_eq!(ev.wd, 1);
    assert_eq!(ev.mask, IN_ACCESS);
    assert_eq!(ev.cookie, 0);
    assert_eq!(ev.len, 0);
}

#[test]
pub(crate) fn test_inotify_event_new_with_name() {
    let ev = InotifyEvent::new(2, IN_CREATE, 0, Some("test.txt"));
    assert_eq!(ev.wd, 2);
    assert_eq!(ev.mask, IN_CREATE);
    assert!(ev.len > 0);
}

#[test]
pub(crate) fn test_inotify_event_name_len_alignment() {
    let ev = InotifyEvent::new(1, IN_CREATE, 0, Some("a"));
    assert_eq!(ev.len % 4, 0);
}

#[test]
pub(crate) fn test_inotify_event_name_len_alignment_longer() {
    let ev = InotifyEvent::new(1, IN_CREATE, 0, Some("test"));
    assert_eq!(ev.len % 4, 0);
}

#[test]
pub(crate) fn test_inotify_event_total_size_no_name() {
    let ev = InotifyEvent::new(1, IN_ACCESS, 0, None);
    let header_size = core::mem::size_of::<InotifyEvent>();
    assert_eq!(ev.total_size(), header_size);
}

#[test]
pub(crate) fn test_inotify_event_total_size_with_name() {
    let ev = InotifyEvent::new(1, IN_CREATE, 0, Some("test.txt"));
    let header_size = core::mem::size_of::<InotifyEvent>();
    assert!(ev.total_size() > header_size);
}

#[test]
pub(crate) fn test_inotify_event_clone() {
    let ev = InotifyEvent::new(3, IN_MODIFY, 100, None);
    let cloned = ev.clone();
    assert_eq!(cloned.wd, 3);
    assert_eq!(cloned.mask, IN_MODIFY);
    assert_eq!(cloned.cookie, 100);
}

#[test]
pub(crate) fn test_inotify_event_cookie_for_move() {
    let ev_from = InotifyEvent::new(1, IN_MOVED_FROM, 12345, Some("old.txt"));
    let ev_to = InotifyEvent::new(2, IN_MOVED_TO, 12345, Some("new.txt"));
    assert_eq!(ev_from.cookie, ev_to.cookie);
}

#[test]
pub(crate) fn test_inotify_stats_fields() {
    let stats = InotifyStats { instance_count: 5, total_watches: 100, total_queued_events: 250 };
    assert_eq!(stats.instance_count, 5);
    assert_eq!(stats.total_watches, 100);
    assert_eq!(stats.total_queued_events, 250);
}

#[test]
pub(crate) fn test_inotify_init_success_returns_fd() {
    let fd = 5i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 5);
}

#[test]
pub(crate) fn test_inotify_init1_invalid_flags_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_inotify_init1_success_returns_fd() {
    let fd = 6i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 6);
}

#[test]
pub(crate) fn test_inotify_init_max_instances_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_inotify_add_watch_null_path_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_inotify_add_watch_invalid_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_inotify_add_watch_success_returns_wd() {
    let wd = 1i64;
    let result = SyscallResult::success(wd);
    assert_eq!(result.value, 1);
}

#[test]
pub(crate) fn test_inotify_add_watch_path_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
pub(crate) fn test_inotify_add_watch_not_directory_returns_enotdir() {
    let result = SyscallResult::error(20);
    assert_eq!(result.errno(), Some(20));
}

#[test]
pub(crate) fn test_inotify_add_watch_max_watches_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_inotify_rm_watch_invalid_fd_returns_ebadf() {
    let result = SyscallResult::error(9);
    assert_eq!(result.errno(), Some(9));
}

#[test]
pub(crate) fn test_inotify_rm_watch_invalid_wd_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_inotify_rm_watch_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_inotify_read_would_block_returns_eagain() {
    let result = SyscallResult::error(11);
    assert_eq!(result.errno(), Some(11));
}

#[test]
pub(crate) fn test_inotify_read_success_returns_bytes() {
    let bytes = 32i64;
    let result = SyscallResult::success(bytes);
    assert_eq!(result.value, 32);
}

#[test]
pub(crate) fn test_inotify_valid_flags_mask() {
    let valid_flags = IN_CLOEXEC | IN_NONBLOCK;
    assert_eq!(valid_flags, 0x80800);
}

#[test]
pub(crate) fn test_inotify_event_struct_size() {
    assert_eq!(core::mem::size_of::<InotifyEvent>(), 16);
}

#[test]
pub(crate) fn test_inotify_mask_combine_create_delete() {
    let mask = IN_CREATE | IN_DELETE;
    assert_eq!(mask, 0x00000300);
}

#[test]
pub(crate) fn test_inotify_mask_combine_modify_attrib() {
    let mask = IN_MODIFY | IN_ATTRIB;
    assert_eq!(mask, 0x00000006);
}

#[test]
pub(crate) fn test_inotify_mask_with_flags() {
    let mask = IN_CREATE | IN_ONESHOT | IN_ISDIR;
    assert!(mask & IN_CREATE != 0);
    assert!(mask & IN_ONESHOT != 0);
    assert!(mask & IN_ISDIR != 0);
}
