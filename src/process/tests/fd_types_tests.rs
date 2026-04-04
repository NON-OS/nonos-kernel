use crate::process::fd_types::*;
use crate::process::process_fd_table::ProcessFdTable;

#[test]
fn fd_type_variants() {
    assert_eq!(FdType::File, FdType::File);
    assert_eq!(FdType::Socket, FdType::Socket);
    assert_eq!(FdType::Pipe, FdType::Pipe);
    assert_eq!(FdType::EventFd, FdType::EventFd);
    assert_eq!(FdType::TimerFd, FdType::TimerFd);
    assert_eq!(FdType::SignalFd, FdType::SignalFd);
    assert_eq!(FdType::Epoll, FdType::Epoll);
    assert_eq!(FdType::Directory, FdType::Directory);
    assert_eq!(FdType::Unknown, FdType::Unknown);
}

#[test]
fn fd_type_not_equal_different_variants() {
    assert_ne!(FdType::File, FdType::Socket);
    assert_ne!(FdType::Pipe, FdType::EventFd);
    assert_ne!(FdType::Directory, FdType::Unknown);
}

#[test]
fn fd_entry_new() {
    let entry = FdEntry::new(FdType::File, 42);
    assert_eq!(entry.fd, -1);
    assert_eq!(entry.fd_type, FdType::File);
    assert_eq!(entry.internal_id, 42);
    assert!(!entry.is_read_end);
    assert!(!entry.is_write_end);
    assert_eq!(entry.flags, 0);
    assert_eq!(entry.status_flags, 0);
}

#[test]
fn fd_entry_with_pipe_read() {
    let entry = FdEntry::with_pipe(100, true);
    assert_eq!(entry.fd, -1);
    assert_eq!(entry.fd_type, FdType::Pipe);
    assert_eq!(entry.internal_id, 100);
    assert!(entry.is_read_end);
    assert!(!entry.is_write_end);
}

#[test]
fn fd_entry_with_pipe_write() {
    let entry = FdEntry::with_pipe(200, false);
    assert_eq!(entry.fd, -1);
    assert_eq!(entry.fd_type, FdType::Pipe);
    assert_eq!(entry.internal_id, 200);
    assert!(!entry.is_read_end);
    assert!(entry.is_write_end);
}

#[test]
fn fd_entry_is_cloexec() {
    let mut entry = FdEntry::new(FdType::File, 0);
    assert!(!entry.is_cloexec());
    entry.flags = FD_CLOEXEC;
    assert!(entry.is_cloexec());
}

#[test]
fn fd_cloexec_constant() {
    assert_eq!(FD_CLOEXEC, 1);
}

#[test]
fn max_process_fds_constant() {
    assert_eq!(MAX_PROCESS_FDS, 1024);
}

#[test]
fn stdio_fds_constant() {
    assert_eq!(STDIO_FDS, 3);
}

#[test]
fn fd_entry_clone() {
    let entry1 = FdEntry::new(FdType::Socket, 55);
    let entry2 = entry1.clone();
    assert_eq!(entry1.fd, entry2.fd);
    assert_eq!(entry1.fd_type, entry2.fd_type);
    assert_eq!(entry1.internal_id, entry2.internal_id);
}

#[test]
fn fd_table_stats_default() {
    let stats = FdTableStats {
        total_fds: 0,
        file_count: 0,
        socket_count: 0,
        pipe_count: 0,
        eventfd_count: 0,
        timerfd_count: 0,
        signalfd_count: 0,
        epoll_count: 0,
    };
    assert_eq!(stats.total_fds, 0);
    assert_eq!(stats.file_count, 0);
    assert_eq!(stats.socket_count, 0);
}

#[test]
fn process_fd_table_new() {
    let table = ProcessFdTable::new();
    assert_eq!(table.count(), 0);
}

#[test]
fn process_fd_table_allocate() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert!(fd >= STDIO_FDS);
    assert_eq!(table.count(), 1);
}

#[test]
fn process_fd_table_allocate_at() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate_at(10, entry).unwrap();
    assert_eq!(fd, 10);
    assert!(table.is_valid(10));
}

#[test]
fn process_fd_table_allocate_min() {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::File, 2);
    table.allocate_at(5, entry1).unwrap();
    let fd = table.allocate_min(entry2, 5).unwrap();
    assert!(fd > 5);
}

#[test]
fn process_fd_table_get() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::Socket, 42);
    let fd = table.allocate(entry).unwrap();
    let retrieved = table.get(fd).unwrap();
    assert_eq!(retrieved.fd_type, FdType::Socket);
    assert_eq!(retrieved.internal_id, 42);
}

#[test]
fn process_fd_table_remove() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert!(table.is_valid(fd));
    let removed = table.remove(fd);
    assert!(removed.is_some());
    assert!(!table.is_valid(fd));
}

#[test]
fn process_fd_table_is_valid() {
    let table = ProcessFdTable::new();
    assert!(!table.is_valid(10));
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert!(table.is_valid(fd));
}

#[test]
fn process_fd_table_get_type() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::EventFd, 1);
    let fd = table.allocate(entry).unwrap();
    assert_eq!(table.get_type(fd), Some(FdType::EventFd));
}

#[test]
fn process_fd_table_close_all() {
    let table = ProcessFdTable::new();
    table.allocate(FdEntry::new(FdType::File, 1)).unwrap();
    table.allocate(FdEntry::new(FdType::Socket, 2)).unwrap();
    table.allocate(FdEntry::new(FdType::Pipe, 3)).unwrap();
    assert_eq!(table.count(), 3);
    table.close_all();
    assert_eq!(table.count(), 0);
}

#[test]
fn process_fd_table_cloexec() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert_eq!(table.get_cloexec(fd), Some(false));
    assert!(table.set_cloexec(fd, true));
    assert_eq!(table.get_cloexec(fd), Some(true));
    assert!(table.set_cloexec(fd, false));
    assert_eq!(table.get_cloexec(fd), Some(false));
}

#[test]
fn process_fd_table_status_flags() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert_eq!(table.get_status_flags(fd), Some(0));
    assert!(table.set_status_flags(fd, 0x800));
    assert_eq!(table.get_status_flags(fd), Some(0x800));
}

#[test]
fn process_fd_table_dup() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    table.set_cloexec(fd, true);
    let new_fd = table.dup(fd).unwrap();
    assert_ne!(fd, new_fd);
    assert_eq!(table.get_type(new_fd), Some(FdType::File));
    assert_eq!(table.get_cloexec(new_fd), Some(false));
}

#[test]
fn process_fd_table_dup2() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    let new_fd = table.dup2(fd, 100).unwrap();
    assert_eq!(new_fd, 100);
    assert!(table.is_valid(100));
    assert_eq!(table.get_type(100), Some(FdType::File));
}

#[test]
fn process_fd_table_dup2_same_fd() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    let result = table.dup2(fd, fd);
    assert_eq!(result, Some(fd));
}

#[test]
fn process_fd_table_dup2_replaces_existing() {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::Socket, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.dup2(fd1, fd2).unwrap();
    assert_eq!(table.get_type(fd2), Some(FdType::File));
}

#[test]
fn process_fd_table_close_cloexec() {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::File, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.set_cloexec(fd1, true);
    assert_eq!(table.count(), 2);
    table.close_cloexec();
    assert_eq!(table.count(), 1);
    assert!(!table.is_valid(fd1));
    assert!(table.is_valid(fd2));
}

#[test]
fn process_fd_table_fork() {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::Socket, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.set_cloexec(fd1, true);
    let forked = table.fork();
    assert_eq!(forked.count(), 1);
    assert!(!forked.is_valid(fd1));
    assert!(forked.is_valid(fd2));
}

#[test]
fn process_fd_table_stats() {
    let table = ProcessFdTable::new();
    table.allocate(FdEntry::new(FdType::File, 1)).unwrap();
    table.allocate(FdEntry::new(FdType::File, 2)).unwrap();
    table.allocate(FdEntry::new(FdType::Socket, 3)).unwrap();
    table.allocate(FdEntry::new(FdType::Pipe, 4)).unwrap();
    table.allocate(FdEntry::new(FdType::EventFd, 5)).unwrap();
    let stats = table.stats();
    assert_eq!(stats.total_fds, 5);
    assert_eq!(stats.file_count, 2);
    assert_eq!(stats.socket_count, 1);
    assert_eq!(stats.pipe_count, 1);
    assert_eq!(stats.eventfd_count, 1);
}

#[test]
fn process_fd_table_allocate_at_invalid() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    assert!(table.allocate_at(-1, entry.clone()).is_none());
    assert!(table.allocate_at(MAX_PROCESS_FDS, entry).is_none());
}

#[test]
fn process_fd_table_allocate_min_invalid() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    assert!(table.allocate_min(entry.clone(), -1).is_none());
    assert!(table.allocate_min(entry, MAX_PROCESS_FDS).is_none());
}

#[test]
fn process_fd_table_dup2_invalid_new_fd() {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    assert!(table.dup2(fd, -1).is_none());
    assert!(table.dup2(fd, MAX_PROCESS_FDS).is_none());
}

#[test]
fn process_fd_table_dup_nonexistent() {
    let table = ProcessFdTable::new();
    assert!(table.dup(999).is_none());
}

#[test]
fn process_fd_table_set_cloexec_nonexistent() {
    let table = ProcessFdTable::new();
    assert!(!table.set_cloexec(999, true));
}

#[test]
fn process_fd_table_set_status_flags_nonexistent() {
    let table = ProcessFdTable::new();
    assert!(!table.set_status_flags(999, 0x100));
}
