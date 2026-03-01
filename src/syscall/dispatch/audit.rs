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

extern crate alloc;

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

use crate::syscall::{SyscallNumber, SyscallResult};

pub static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
pub static AUDIT_VERBOSE: AtomicBool = AtomicBool::new(false);

pub static SYSCALL_STATS: SyscallStats = SyscallStats::new();

pub struct SyscallStats {
    pub total_calls: AtomicU64,
    pub successful_calls: AtomicU64,
    pub failed_calls: AtomicU64,
    pub permission_denied: AtomicU64,
    pub audit_entries: AtomicU64,
}

impl SyscallStats {
    pub const fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            successful_calls: AtomicU64::new(0),
            failed_calls: AtomicU64::new(0),
            permission_denied: AtomicU64::new(0),
            audit_entries: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallAuditEntry {
    pub timestamp_ms: u64,
    pub syscall_num: u64,
    pub syscall_name: &'static str,
    pub pid: u32,
    pub result: i64,
    pub args: [u64; 4],
    pub success: bool,
}

pub static AUDIT_LOG: Mutex<AuditLog> = Mutex::new(AuditLog::new());

pub struct AuditLog {
    entries: [Option<SyscallAuditEntry>; 256],
    head: usize,
    count: usize,
}

impl AuditLog {
    pub const fn new() -> Self {
        const NONE: Option<SyscallAuditEntry> = None;
        Self {
            entries: [NONE; 256],
            head: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, entry: SyscallAuditEntry) {
        self.entries[self.head] = Some(entry);
        self.head = (self.head + 1) % 256;
        if self.count < 256 {
            self.count += 1;
        }
    }
}

pub fn audit_syscall(syscall: SyscallNumber, args: [u64; 4], result: &SyscallResult) {
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let syscall_name = match syscall {
        SyscallNumber::Read => "read",
        SyscallNumber::Write => "write",
        SyscallNumber::Open => "open",
        SyscallNumber::Close => "close",
        SyscallNumber::Stat => "stat",
        SyscallNumber::Fstat => "fstat",
        SyscallNumber::Lstat => "lstat",
        SyscallNumber::Poll => "poll",
        SyscallNumber::Lseek => "lseek",
        SyscallNumber::Ioctl => "ioctl",
        SyscallNumber::Access => "access",
        SyscallNumber::Fcntl => "fcntl",
        SyscallNumber::Ftruncate => "ftruncate",
        SyscallNumber::Creat => "creat",
        SyscallNumber::Readlink => "readlink",
        SyscallNumber::Sendfile => "sendfile",
        SyscallNumber::Dup => "dup",
        SyscallNumber::Dup2 => "dup2",
        SyscallNumber::Dup3 => "dup3",
        SyscallNumber::Pipe => "pipe",
        SyscallNumber::Pipe2 => "pipe2",
        SyscallNumber::Getdents => "getdents",
        SyscallNumber::Getdents64 => "getdents64",
        SyscallNumber::Getcwd => "getcwd",
        SyscallNumber::Chdir => "chdir",
        SyscallNumber::Mkdir => "mkdir",
        SyscallNumber::Rmdir => "rmdir",
        SyscallNumber::Unlink => "unlink",
        SyscallNumber::Rename => "rename",
        SyscallNumber::Mmap => "mmap",
        SyscallNumber::Mprotect => "mprotect",
        SyscallNumber::Munmap => "munmap",
        SyscallNumber::Brk => "brk",
        SyscallNumber::Mremap => "mremap",
        SyscallNumber::RtSigaction => "rt_sigaction",
        SyscallNumber::RtSigprocmask => "rt_sigprocmask",
        SyscallNumber::RtSigreturn => "rt_sigreturn",
        SyscallNumber::RtSigsuspend => "rt_sigsuspend",
        SyscallNumber::RtSigpending => "rt_sigpending",
        SyscallNumber::RtSigtimedwait => "rt_sigtimedwait",
        SyscallNumber::RtSigqueueinfo => "rt_sigqueueinfo",
        SyscallNumber::Sigaltstack => "sigaltstack",
        SyscallNumber::Kill => "kill",
        SyscallNumber::Tkill => "tkill",
        SyscallNumber::Tgkill => "tgkill",
        SyscallNumber::Exit => "exit",
        SyscallNumber::ExitGroup => "exit_group",
        SyscallNumber::Fork => "fork",
        SyscallNumber::Vfork => "vfork",
        SyscallNumber::Execve => "execve",
        SyscallNumber::Wait4 => "wait4",
        SyscallNumber::Waitid => "waitid",
        SyscallNumber::Nanosleep => "nanosleep",
        SyscallNumber::Yield => "yield",
        SyscallNumber::Futex => "futex",
        SyscallNumber::Getpid => "getpid",
        SyscallNumber::Getppid => "getppid",
        SyscallNumber::Gettid => "gettid",
        SyscallNumber::Getuid => "getuid",
        SyscallNumber::Geteuid => "geteuid",
        SyscallNumber::Getgid => "getgid",
        SyscallNumber::Getegid => "getegid",
        SyscallNumber::Uname => "uname",
        SyscallNumber::Gettimeofday => "gettimeofday",
        SyscallNumber::ClockGettime => "clock_gettime",
        SyscallNumber::Getrusage => "getrusage",
        SyscallNumber::Socket => "socket",
        SyscallNumber::Connect => "connect",
        SyscallNumber::Accept => "accept",
        SyscallNumber::Sendto => "sendto",
        SyscallNumber::Recvfrom => "recvfrom",
        SyscallNumber::Sendmsg => "sendmsg",
        SyscallNumber::Recvmsg => "recvmsg",
        SyscallNumber::Shutdown => "shutdown",
        SyscallNumber::Bind => "bind",
        SyscallNumber::Listen => "listen",
        SyscallNumber::Getsockname => "getsockname",
        SyscallNumber::Getpeername => "getpeername",
        SyscallNumber::Socketpair => "socketpair",
        SyscallNumber::Setsockopt => "setsockopt",
        SyscallNumber::Getsockopt => "getsockopt",
        SyscallNumber::IpcSend => "ipc_send",
        SyscallNumber::IpcRecv => "ipc_recv",
        SyscallNumber::IpcCreate => "ipc_create",
        SyscallNumber::IpcDestroy => "ipc_destroy",
        SyscallNumber::CryptoRandom => "crypto_random",
        SyscallNumber::CryptoHash => "crypto_hash",
        SyscallNumber::CryptoSign => "crypto_sign",
        SyscallNumber::CryptoVerify => "crypto_verify",
        SyscallNumber::CryptoEncrypt => "crypto_encrypt",
        SyscallNumber::CryptoDecrypt => "crypto_decrypt",
        SyscallNumber::CryptoKeyGen => "crypto_keygen",
        SyscallNumber::CryptoZkProve => "crypto_zk_prove",
        SyscallNumber::CryptoZkVerify => "crypto_zk_verify",
        SyscallNumber::IoPortRead => "io_port_read",
        SyscallNumber::IoPortWrite => "io_port_write",
        SyscallNumber::MmioMap => "mmio_map",
        SyscallNumber::DebugLog => "debug_log",
        SyscallNumber::DebugTrace => "debug_trace",
        SyscallNumber::AdminReboot => "admin_reboot",
        SyscallNumber::AdminShutdown => "admin_shutdown",
        SyscallNumber::AdminModLoad => "admin_modload",
        SyscallNumber::AdminCapGrant => "admin_cap_grant",
        SyscallNumber::AdminCapRevoke => "admin_cap_revoke",
        _ => "unknown",
    };

    let pid = crate::process::current_process()
        .map(|p| p.pid)
        .unwrap_or(0);

    let entry = SyscallAuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        syscall_num: syscall as u64,
        syscall_name,
        pid,
        result: result.value,
        args,
        success: result.value >= 0,
    };

    if AUDIT_VERBOSE.load(Ordering::Relaxed) {
        crate::log::info!(
            "syscall: {}({:x},{:x},{:x},{:x}) = {} [pid={}]",
            syscall_name, args[0], args[1], args[2], args[3],
            result.value, pid
        );
    }

    let mut log = AUDIT_LOG.lock();
    log.push(entry);
    SYSCALL_STATS.audit_entries.fetch_add(1, Ordering::Relaxed);
}

pub fn set_audit_enabled(enabled: bool) {
    AUDIT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_audit_verbose(verbose: bool) {
    AUDIT_VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn get_syscall_stats() -> (u64, u64, u64, u64) {
    (
        SYSCALL_STATS.total_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.successful_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.failed_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.permission_denied.load(Ordering::Relaxed),
    )
}

pub fn get_audit_log(max_entries: usize) -> alloc::vec::Vec<SyscallAuditEntry> {
    let log = AUDIT_LOG.lock();
    let mut result = alloc::vec::Vec::with_capacity(max_entries.min(log.count));

    let start = if log.count >= 256 {
        log.head
    } else {
        0
    };

    for i in 0..log.count.min(max_entries) {
        let idx = (start + log.count - 1 - i) % 256;
        if let Some(entry) = &log.entries[idx] {
            result.push(entry.clone());
        }
    }

    result
}

pub fn clear_audit_log() {
    let mut log = AUDIT_LOG.lock();
    *log = AuditLog::new();
}
