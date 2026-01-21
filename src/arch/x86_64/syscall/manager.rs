// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::{vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::{RwLock, Mutex};

use super::error::SyscallError;
use super::numbers::*;
use super::msr;
use super::security::SecurityConfig;
use super::stats::{SyscallStats, SyscallRecord, InternalStats};
use super::handlers;
use super::util::read_user_string;

pub type SyscallHandler = fn(u64, u64, u64, u64, u64, u64) -> u64;

#[derive(Debug)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: &'static str,
    pub handler: SyscallHandler,
    pub call_count: AtomicU64,
    pub total_time_ns: AtomicU64,
    pub error_count: AtomicU64,
    pub last_called_ns: AtomicU64,
}

impl SyscallInfo {
    pub const fn new(number: u64, name: &'static str, handler: SyscallHandler) -> Self {
        Self {
            number,
            name,
            handler,
            call_count: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            last_called_ns: AtomicU64::new(0),
        }
    }
}

pub struct SyscallManager {
    table: RwLock<BTreeMap<u64, SyscallInfo>>,
    original_hash: RwLock<[u8; 32]>,
    audit_log: Mutex<Vec<SyscallRecord>>,
    stats: InternalStats,
    config: RwLock<SecurityConfig>,
    fork_counter: AtomicU32,
    fork_reset_time: AtomicU64,
}

impl SyscallManager {
    pub const fn new() -> Self {
        Self {
            table: RwLock::new(BTreeMap::new()),
            original_hash: RwLock::new([0u8; 32]),
            audit_log: Mutex::new(Vec::new()),
            stats: InternalStats::new(),
            config: RwLock::new(SecurityConfig {
                max_fork_rate: 100,
                validate_paths: true,
                verify_executables: true,
                max_syscall_rate: 0,
                audit_enabled: true,
                max_audit_records: 1000,
            }),
            fork_counter: AtomicU32::new(0),
            fork_reset_time: AtomicU64::new(0),
        }
    }

    pub fn init(&self) -> Result<(), SyscallError> {
        if INITIALIZED.load(Ordering::SeqCst) {
            return Err(SyscallError::AlreadyInitialized);
        }

        self.setup_fast_syscalls()?;
        self.initialize_table();
        self.compute_table_hash();

        INITIALIZED.store(true, Ordering::SeqCst);
        crate::log_info!("Syscall subsystem initialized");

        Ok(())
    }

    fn setup_fast_syscalls(&self) -> Result<(), SyscallError> {
        msr::setup_star(0x08, 0x10, 0x1B, 0x23);
        let entry_point = syscall_entry_asm as *const () as u64;
        msr::setup_lstar(entry_point);
        msr::setup_fmask();
        msr::enable_sce();
        Ok(())
    }

    fn initialize_table(&self) {
        let mut table = self.table.write();

        table.insert(SYS_READ, SyscallInfo::new(SYS_READ, "read", handlers::syscall_read));
        table.insert(SYS_WRITE, SyscallInfo::new(SYS_WRITE, "write", handlers::syscall_write));
        table.insert(SYS_OPEN, SyscallInfo::new(SYS_OPEN, "open", handlers::syscall_open));
        table.insert(SYS_CLOSE, SyscallInfo::new(SYS_CLOSE, "close", handlers::syscall_close));
        table.insert(SYS_LSEEK, SyscallInfo::new(SYS_LSEEK, "lseek", handlers::syscall_lseek));
        table.insert(SYS_PREAD64, SyscallInfo::new(SYS_PREAD64, "pread64", handlers::syscall_pread64));
        table.insert(SYS_PWRITE64, SyscallInfo::new(SYS_PWRITE64, "pwrite64", handlers::syscall_pwrite64));

        table.insert(SYS_STAT, SyscallInfo::new(SYS_STAT, "stat", handlers::syscall_stat));
        table.insert(SYS_FSTAT, SyscallInfo::new(SYS_FSTAT, "fstat", handlers::syscall_fstat));
        table.insert(SYS_LSTAT, SyscallInfo::new(SYS_LSTAT, "lstat", handlers::syscall_lstat));

        table.insert(SYS_MMAP, SyscallInfo::new(SYS_MMAP, "mmap", handlers::syscall_mmap));
        table.insert(SYS_MPROTECT, SyscallInfo::new(SYS_MPROTECT, "mprotect", handlers::syscall_mprotect));
        table.insert(SYS_MUNMAP, SyscallInfo::new(SYS_MUNMAP, "munmap", handlers::syscall_munmap));
        table.insert(SYS_BRK, SyscallInfo::new(SYS_BRK, "brk", handlers::syscall_brk));

        table.insert(SYS_GETPID, SyscallInfo::new(SYS_GETPID, "getpid", handlers::syscall_getpid));
        table.insert(SYS_GETPPID, SyscallInfo::new(SYS_GETPPID, "getppid", handlers::syscall_getppid));
        table.insert(SYS_GETUID, SyscallInfo::new(SYS_GETUID, "getuid", handlers::syscall_getuid));
        table.insert(SYS_GETGID, SyscallInfo::new(SYS_GETGID, "getgid", handlers::syscall_getgid));
        table.insert(SYS_GETEUID, SyscallInfo::new(SYS_GETEUID, "geteuid", handlers::syscall_geteuid));
        table.insert(SYS_GETEGID, SyscallInfo::new(SYS_GETEGID, "getegid", handlers::syscall_getegid));
        table.insert(SYS_FORK, SyscallInfo::new(SYS_FORK, "fork", handlers::syscall_fork));
        table.insert(SYS_CLONE, SyscallInfo::new(SYS_CLONE, "clone", handlers::syscall_clone));
        table.insert(SYS_EXECVE, SyscallInfo::new(SYS_EXECVE, "execve", handlers::syscall_execve));
        table.insert(SYS_EXIT, SyscallInfo::new(SYS_EXIT, "exit", handlers::syscall_exit));
        table.insert(SYS_WAIT4, SyscallInfo::new(SYS_WAIT4, "wait4", handlers::syscall_wait4));

        table.insert(SYS_RT_SIGACTION, SyscallInfo::new(SYS_RT_SIGACTION, "rt_sigaction", handlers::syscall_rt_sigaction));
        table.insert(SYS_RT_SIGPROCMASK, SyscallInfo::new(SYS_RT_SIGPROCMASK, "rt_sigprocmask", handlers::syscall_rt_sigprocmask));
        table.insert(SYS_RT_SIGRETURN, SyscallInfo::new(SYS_RT_SIGRETURN, "rt_sigreturn", handlers::syscall_rt_sigreturn));
        table.insert(SYS_KILL, SyscallInfo::new(SYS_KILL, "kill", handlers::syscall_kill));

        table.insert(SYS_IOCTL, SyscallInfo::new(SYS_IOCTL, "ioctl", handlers::syscall_ioctl));

        table.insert(SYS_DUP, SyscallInfo::new(SYS_DUP, "dup", handlers::syscall_dup));
        table.insert(SYS_DUP2, SyscallInfo::new(SYS_DUP2, "dup2", handlers::syscall_dup2));
        table.insert(SYS_PIPE, SyscallInfo::new(SYS_PIPE, "pipe", handlers::syscall_pipe));

        table.insert(SYS_NANOSLEEP, SyscallInfo::new(SYS_NANOSLEEP, "nanosleep", handlers::syscall_nanosleep));
        table.insert(SYS_SCHED_YIELD, SyscallInfo::new(SYS_SCHED_YIELD, "sched_yield", handlers::syscall_sched_yield));
        table.insert(SYS_ALARM, SyscallInfo::new(SYS_ALARM, "alarm", handlers::syscall_alarm));

        table.insert(SYS_UNAME, SyscallInfo::new(SYS_UNAME, "uname", handlers::syscall_uname));

        table.insert(SYS_SOCKET, SyscallInfo::new(SYS_SOCKET, "socket", handlers::syscall_socket));
        table.insert(SYS_CONNECT, SyscallInfo::new(SYS_CONNECT, "connect", handlers::syscall_connect));
        table.insert(SYS_ACCEPT, SyscallInfo::new(SYS_ACCEPT, "accept", handlers::syscall_accept));
        table.insert(SYS_BIND, SyscallInfo::new(SYS_BIND, "bind", handlers::syscall_bind));
        table.insert(SYS_LISTEN, SyscallInfo::new(SYS_LISTEN, "listen", handlers::syscall_listen));
        table.insert(SYS_SENDTO, SyscallInfo::new(SYS_SENDTO, "sendto", handlers::syscall_sendto));
        table.insert(SYS_RECVFROM, SyscallInfo::new(SYS_RECVFROM, "recvfrom", handlers::syscall_recvfrom));
    }

    fn compute_table_hash(&self) {
        let table = self.table.read();
        let mut data = Vec::new();

        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }

        let hash = crate::crypto::hash::sha3_256(&data);
        let mut original = self.original_hash.write();
        *original = hash;
    }

    pub fn dispatch(&self, number: u64, args: [u64; 6]) -> u64 {
        let start_time = crate::time::now_ns();
        self.stats.total_calls.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.validate_syscall(number, &args) {
            self.stats.blocked_calls.fetch_add(1, Ordering::Relaxed);
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return e.to_errno() as u64;
        }

        let handler = {
            let table = self.table.read();
            if let Some(info) = table.get(&number) {
                info.call_count.fetch_add(1, Ordering::Relaxed);
                info.last_called_ns.store(start_time, Ordering::Relaxed);
                info.handler
            } else {
                self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                return SyscallError::HandlerNotFound { number }.to_errno() as u64;
            }
        };

        let result = handler(args[0], args[1], args[2], args[3], args[4], args[5]);
        let end_time = crate::time::now_ns();
        let duration = end_time.saturating_sub(start_time);
        self.stats.total_time_ns.fetch_add(duration, Ordering::Relaxed);

        {
            let table = self.table.read();
            if let Some(info) = table.get(&number) {
                info.total_time_ns.fetch_add(duration, Ordering::Relaxed);
                if (result as i64) < 0 {
                    info.error_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let config = self.config.read();
        if config.audit_enabled {
            let record = SyscallRecord {
                number,
                args,
                return_value: result,
                timestamp_ns: start_time,
                duration_ns: duration,
                process_id: crate::process::nonos_core::current_pid().unwrap_or(0) as u32,
                thread_id: 0,
                blocked: false,
            };
            drop(config);
            self.add_audit_record(record);
        }

        result
    }

    fn validate_syscall(&self, number: u64, args: &[u64; 6]) -> Result<(), SyscallError> {
        let config = self.config.read();

        match number {
            SYS_OPEN | SYS_STAT | SYS_LSTAT | SYS_ACCESS => {
                if config.validate_paths {
                    self.validate_user_path(args[0])?;
                }
            }

            SYS_FORK | SYS_VFORK | SYS_CLONE => {
                if config.max_fork_rate > 0 {
                    self.check_fork_rate(config.max_fork_rate)?;
                }
            }

            SYS_EXECVE => {
                if config.verify_executables {
                    self.validate_user_path(args[0])?;
                    self.verify_executable(args[0])?;
                }
            }

            _ => {}
        }

        Ok(())
    }

    fn validate_user_path(&self, path_ptr: u64) -> Result<(), SyscallError> {
        if path_ptr == 0 {
            return Err(SyscallError::InvalidPath { address: 0 });
        }

        if path_ptr >= 0xFFFF_8000_0000_0000 {
            return Err(SyscallError::InvalidPath { address: path_ptr });
        }

        if path_ptr > 0x7FFF_FFFF_FFFF && path_ptr < 0xFFFF_8000_0000_0000 {
            return Err(SyscallError::InvalidPath { address: path_ptr });
        }

        Ok(())
    }

    fn check_fork_rate(&self, max_rate: u32) -> Result<(), SyscallError> {
        let now = crate::time::now_ns();
        let last_reset = self.fork_reset_time.load(Ordering::Relaxed);

        if now.saturating_sub(last_reset) >= 1_000_000_000 {
            self.fork_counter.store(0, Ordering::Relaxed);
            self.fork_reset_time.store(now, Ordering::Relaxed);
        }

        let count = self.fork_counter.fetch_add(1, Ordering::Relaxed);
        if count >= max_rate {
            return Err(SyscallError::RateLimitExceeded { syscall: SYS_FORK });
        }

        Ok(())
    }

    fn verify_executable(&self, path_ptr: u64) -> Result<(), SyscallError> {
        let path = match read_user_string(path_ptr) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let file_contents = match crate::fs::read_file(&path) {
            Ok(data) => data,
            Err(_) => return Ok(()),
        };

        let actual_hash = crate::crypto::hash::sha3_256(&file_contents);

        if let Some(trusted_hash) = crate::security::nonos_trusted_hashes::get_trusted_hash(&path) {
            if actual_hash != trusted_hash {
                self.stats.security_violations.fetch_add(1, Ordering::Relaxed);
                return Err(SyscallError::SecurityViolation {
                    reason: "Executable integrity check failed - hash mismatch",
                });
            }
        }

        Ok(())
    }

    fn add_audit_record(&self, record: SyscallRecord) {
        let config = self.config.read();
        let max_records = config.max_audit_records;
        drop(config);

        let mut log = self.audit_log.lock();
        if log.len() >= max_records {
            log.remove(0);
        }
        log.push(record);
    }

    pub fn detect_hooks(&self) -> bool {
        let table = self.table.read();
        let mut data = Vec::new();

        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }

        let current_hash = crate::crypto::hash::sha3_256(&data);
        let original = self.original_hash.read();

        self.stats.integrity_checks.fetch_add(1, Ordering::Relaxed);
        self.stats.last_integrity_check_ns.store(crate::time::now_ns(), Ordering::Relaxed);

        if current_hash != *original {
            self.stats.hook_detections.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    pub fn verify_integrity(&self) -> bool {
        !self.detect_hooks()
    }

    pub fn get_statistics(&self) -> SyscallStats {
        self.stats.snapshot()
    }

    pub fn get_audit_log(&self) -> Vec<SyscallRecord> {
        self.audit_log.lock().clone()
    }

    pub fn configure(&self, config: SecurityConfig) {
        *self.config.write() = config;
    }
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static SYSCALL_MANAGER: SyscallManager = SyscallManager::new();

#[unsafe(naked)]
extern "C" fn syscall_entry_asm() {
    core::arch::naked_asm!(
            "swapgs",
            "mov gs:0x10, rsp",
            "mov rsp, gs:0x08",
            "push rbp",
            "push r11",
            "push rcx",
            "push r10",
            "push r9",
            "push r8",
            "mov rcx, r10",
            "push rax",
            "mov rdi, rax",
            "call {handler}",
            "add rsp, 8",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop rcx",
            "pop r11",
            "pop rbp",
            "mov rsp, gs:0x10",
            "swapgs",
            "sysretq",
            handler = sym syscall_handler,
        );
}

#[no_mangle]
pub(super) extern "C" fn syscall_handler(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    SYSCALL_MANAGER.dispatch(number, [arg1, arg2, arg3, arg4, arg5, arg6])
}

pub fn init() -> Result<(), SyscallError> {
    SYSCALL_MANAGER.init()
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

pub fn configure_security(config: SecurityConfig) {
    SYSCALL_MANAGER.configure(config);
}

pub fn detect_syscall_hooks() -> bool {
    SYSCALL_MANAGER.detect_hooks()
}

pub fn get_recent_calls() -> Vec<SyscallRecord> {
    SYSCALL_MANAGER.get_audit_log()
}

pub fn get_syscall_stats() -> SyscallStats {
    SYSCALL_MANAGER.get_statistics()
}

pub fn verify_syscall_table_integrity() -> bool {
    SYSCALL_MANAGER.verify_integrity()
}

pub mod security {
    pub use super::super::security::*;
}
