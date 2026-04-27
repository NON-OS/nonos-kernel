use crate::process::fd_types::*;
use crate::process::process_fd_table::ProcessFdTable;
use crate::test::framework::TestResult;

pub fn fd_type_variants() -> TestResult {
    if FdType::File != FdType::File {
        return TestResult::Fail;
    }
    if FdType::Socket != FdType::Socket {
        return TestResult::Fail;
    }
    if FdType::Pipe != FdType::Pipe {
        return TestResult::Fail;
    }
    if FdType::EventFd != FdType::EventFd {
        return TestResult::Fail;
    }
    if FdType::TimerFd != FdType::TimerFd {
        return TestResult::Fail;
    }
    if FdType::SignalFd != FdType::SignalFd {
        return TestResult::Fail;
    }
    if FdType::Epoll != FdType::Epoll {
        return TestResult::Fail;
    }
    if FdType::Directory != FdType::Directory {
        return TestResult::Fail;
    }
    if FdType::Unknown != FdType::Unknown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_type_not_equal_different_variants() -> TestResult {
    if FdType::File == FdType::Socket {
        return TestResult::Fail;
    }
    if FdType::Pipe == FdType::EventFd {
        return TestResult::Fail;
    }
    if FdType::Directory == FdType::Unknown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_entry_new() -> TestResult {
    let entry = FdEntry::new(FdType::File, 42);
    if entry.fd != -1 {
        return TestResult::Fail;
    }
    if entry.fd_type != FdType::File {
        return TestResult::Fail;
    }
    if entry.internal_id != 42 {
        return TestResult::Fail;
    }
    if entry.is_read_end {
        return TestResult::Fail;
    }
    if entry.is_write_end {
        return TestResult::Fail;
    }
    if entry.flags != 0 {
        return TestResult::Fail;
    }
    if entry.status_flags != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_entry_with_pipe_read() -> TestResult {
    let entry = FdEntry::with_pipe(100, true);
    if entry.fd != -1 {
        return TestResult::Fail;
    }
    if entry.fd_type != FdType::Pipe {
        return TestResult::Fail;
    }
    if entry.internal_id != 100 {
        return TestResult::Fail;
    }
    if !entry.is_read_end {
        return TestResult::Fail;
    }
    if entry.is_write_end {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_entry_with_pipe_write() -> TestResult {
    let entry = FdEntry::with_pipe(200, false);
    if entry.fd != -1 {
        return TestResult::Fail;
    }
    if entry.fd_type != FdType::Pipe {
        return TestResult::Fail;
    }
    if entry.internal_id != 200 {
        return TestResult::Fail;
    }
    if entry.is_read_end {
        return TestResult::Fail;
    }
    if !entry.is_write_end {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_entry_is_cloexec() -> TestResult {
    let mut entry = FdEntry::new(FdType::File, 0);
    if entry.is_cloexec() {
        return TestResult::Fail;
    }
    entry.flags = FD_CLOEXEC;
    if !entry.is_cloexec() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_cloexec_constant() -> TestResult {
    if FD_CLOEXEC != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn max_process_fds_constant() -> TestResult {
    if MAX_PROCESS_FDS != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn stdio_fds_constant() -> TestResult {
    if STDIO_FDS != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_entry_clone() -> TestResult {
    let entry1 = FdEntry::new(FdType::Socket, 55);
    let entry2 = entry1.clone();
    if entry1.fd != entry2.fd {
        return TestResult::Fail;
    }
    if entry1.fd_type != entry2.fd_type {
        return TestResult::Fail;
    }
    if entry1.internal_id != entry2.internal_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn fd_table_stats_default() -> TestResult {
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
    if stats.total_fds != 0 {
        return TestResult::Fail;
    }
    if stats.file_count != 0 {
        return TestResult::Fail;
    }
    if stats.socket_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_new() -> TestResult {
    let table = ProcessFdTable::new();
    if table.count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_allocate() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if fd < STDIO_FDS {
        return TestResult::Fail;
    }
    if table.count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_allocate_at() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate_at(10, entry).unwrap();
    if fd != 10 {
        return TestResult::Fail;
    }
    if !table.is_valid(10) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_allocate_min() -> TestResult {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::File, 2);
    table.allocate_at(5, entry1).unwrap();
    let fd = table.allocate_min(entry2, 5).unwrap();
    if fd <= 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_get() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::Socket, 42);
    let fd = table.allocate(entry).unwrap();
    let retrieved = table.get(fd).unwrap();
    if retrieved.fd_type != FdType::Socket {
        return TestResult::Fail;
    }
    if retrieved.internal_id != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_remove() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if !table.is_valid(fd) {
        return TestResult::Fail;
    }
    let removed = table.remove(fd);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if table.is_valid(fd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_is_valid() -> TestResult {
    let table = ProcessFdTable::new();
    if table.is_valid(10) {
        return TestResult::Fail;
    }
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if !table.is_valid(fd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_get_type() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::EventFd, 1);
    let fd = table.allocate(entry).unwrap();
    if table.get_type(fd) != Some(FdType::EventFd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_close_all() -> TestResult {
    let table = ProcessFdTable::new();
    table.allocate(FdEntry::new(FdType::File, 1)).unwrap();
    table.allocate(FdEntry::new(FdType::Socket, 2)).unwrap();
    table.allocate(FdEntry::new(FdType::Pipe, 3)).unwrap();
    if table.count() != 3 {
        return TestResult::Fail;
    }
    table.close_all();
    if table.count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_cloexec() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if table.get_cloexec(fd) != Some(false) {
        return TestResult::Fail;
    }
    if !table.set_cloexec(fd, true) {
        return TestResult::Fail;
    }
    if table.get_cloexec(fd) != Some(true) {
        return TestResult::Fail;
    }
    if !table.set_cloexec(fd, false) {
        return TestResult::Fail;
    }
    if table.get_cloexec(fd) != Some(false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_status_flags() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if table.get_status_flags(fd) != Some(0) {
        return TestResult::Fail;
    }
    if !table.set_status_flags(fd, 0x800) {
        return TestResult::Fail;
    }
    if table.get_status_flags(fd) != Some(0x800) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    table.set_cloexec(fd, true);
    let new_fd = table.dup(fd).unwrap();
    if fd == new_fd {
        return TestResult::Fail;
    }
    if table.get_type(new_fd) != Some(FdType::File) {
        return TestResult::Fail;
    }
    if table.get_cloexec(new_fd) != Some(false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup2() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    let new_fd = table.dup2(fd, 100).unwrap();
    if new_fd != 100 {
        return TestResult::Fail;
    }
    if !table.is_valid(100) {
        return TestResult::Fail;
    }
    if table.get_type(100) != Some(FdType::File) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup2_same_fd() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 42);
    let fd = table.allocate(entry).unwrap();
    let result = table.dup2(fd, fd);
    if result != Some(fd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup2_replaces_existing() -> TestResult {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::Socket, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.dup2(fd1, fd2).unwrap();
    if table.get_type(fd2) != Some(FdType::File) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_close_cloexec() -> TestResult {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::File, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.set_cloexec(fd1, true);
    if table.count() != 2 {
        return TestResult::Fail;
    }
    table.close_cloexec();
    if table.count() != 1 {
        return TestResult::Fail;
    }
    if table.is_valid(fd1) {
        return TestResult::Fail;
    }
    if !table.is_valid(fd2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_fork() -> TestResult {
    let table = ProcessFdTable::new();
    let entry1 = FdEntry::new(FdType::File, 1);
    let entry2 = FdEntry::new(FdType::Socket, 2);
    let fd1 = table.allocate(entry1).unwrap();
    let fd2 = table.allocate(entry2).unwrap();
    table.set_cloexec(fd1, true);
    let forked = table.fork();
    if forked.count() != 1 {
        return TestResult::Fail;
    }
    if forked.is_valid(fd1) {
        return TestResult::Fail;
    }
    if !forked.is_valid(fd2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_stats() -> TestResult {
    let table = ProcessFdTable::new();
    table.allocate(FdEntry::new(FdType::File, 1)).unwrap();
    table.allocate(FdEntry::new(FdType::File, 2)).unwrap();
    table.allocate(FdEntry::new(FdType::Socket, 3)).unwrap();
    table.allocate(FdEntry::new(FdType::Pipe, 4)).unwrap();
    table.allocate(FdEntry::new(FdType::EventFd, 5)).unwrap();
    let stats = table.stats();
    if stats.total_fds != 5 {
        return TestResult::Fail;
    }
    if stats.file_count != 2 {
        return TestResult::Fail;
    }
    if stats.socket_count != 1 {
        return TestResult::Fail;
    }
    if stats.pipe_count != 1 {
        return TestResult::Fail;
    }
    if stats.eventfd_count != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_allocate_at_invalid() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    if table.allocate_at(-1, entry.clone()).is_some() {
        return TestResult::Fail;
    }
    if table.allocate_at(MAX_PROCESS_FDS, entry).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_allocate_min_invalid() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    if table.allocate_min(entry.clone(), -1).is_some() {
        return TestResult::Fail;
    }
    if table.allocate_min(entry, MAX_PROCESS_FDS).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup2_invalid_new_fd() -> TestResult {
    let table = ProcessFdTable::new();
    let entry = FdEntry::new(FdType::File, 1);
    let fd = table.allocate(entry).unwrap();
    if table.dup2(fd, -1).is_some() {
        return TestResult::Fail;
    }
    if table.dup2(fd, MAX_PROCESS_FDS).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_dup_nonexistent() -> TestResult {
    let table = ProcessFdTable::new();
    if table.dup(999).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_set_cloexec_nonexistent() -> TestResult {
    let table = ProcessFdTable::new();
    if table.set_cloexec(999, true) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_fd_table_set_status_flags_nonexistent() -> TestResult {
    let table = ProcessFdTable::new();
    if table.set_status_flags(999, 0x100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
