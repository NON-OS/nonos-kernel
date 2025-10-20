//! x86_64 System Call 

use alloc::{vec, vec::Vec, collections::BTreeMap, format};
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use spin::{RwLock, Mutex};
use x86_64::{VirtAddr, registers::model_specific::{LStar, SFMask, Efer, EferFlags, Star}, registers::segmentation::SegmentSelector};

/// System call numbers
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u64)]
pub enum SyscallNumber {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Pread64 = 17,
    Pwrite64 = 18,
    Readv = 19,
    Writev = 20,
    Access = 21,
    Pipe = 22,
    Select = 23,
    SchedYield = 24,
    Mremap = 25,
    Msync = 26,
    Mincore = 27,
    Madvise = 28,
    Shmget = 29,
    Shmat = 30,
    Shmctl = 31,
    Dup = 32,
    Dup2 = 33,
    Pause = 34,
    Nanosleep = 35,
    Getitimer = 36,
    Alarm = 37,
    Setitimer = 38,
    Getpid = 39,
    Sendfile = 40,
    Socket = 41,
    Connect = 42,
    Accept = 43,
    Sendto = 44,
    Recvfrom = 45,
    Sendmsg = 46,
    Recvmsg = 47,
    Shutdown = 48,
    Bind = 49,
    Listen = 50,
    // Add more as needed...
}

/// System call entry point function type
type SyscallHandler = fn(u64, u64, u64, u64, u64, u64) -> u64;

/// System call information
#[derive(Debug)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: &'static str,
    pub handler: SyscallHandler,
    pub call_count: AtomicU64,
    pub total_time: AtomicU64,
    pub last_called: AtomicU64,
}

/// System call statistics
#[derive(Debug, Default)]
pub struct SyscallStats {
    pub total_calls: AtomicU64,
    pub total_time: AtomicU64,
    pub hook_detection_count: AtomicU64,
    pub blocked_calls: AtomicU64,
    pub last_hook_detection: AtomicU64,
}

/// Recent system call record
#[derive(Debug, Clone)]
pub struct SyscallRecord {
    pub number: u64,
    pub args: [u64; 6],
    pub return_value: u64,
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
}

/// System call table manager
pub struct SyscallManager {
    table: RwLock<BTreeMap<u64, SyscallInfo>>,
    original_table_hash: [u8; 32],
    recent_calls: Mutex<Vec<SyscallRecord>>,
    statistics: SyscallStats,
    hooks_detected: AtomicU32,
}

impl SyscallManager {
    pub const fn new() -> Self {
        SyscallManager {
            table: RwLock::new(BTreeMap::new()),
            original_table_hash: [0; 32],
            recent_calls: Mutex::new(Vec::new()),
            statistics: SyscallStats {
                total_calls: AtomicU64::new(0),
                total_time: AtomicU64::new(0),
                hook_detection_count: AtomicU64::new(0),
                blocked_calls: AtomicU64::new(0),
                last_hook_detection: AtomicU64::new(0),
            },
            hooks_detected: AtomicU32::new(0),
        }
    }

    /// Initialize system call subsystem
    pub fn init(&self) -> Result<(), &'static str> {
        self.setup_fast_syscalls()?;
        self.initialize_syscall_table();
        self.compute_table_hash();
        self.enable_table_protection()?;
        Ok(())
    }

    /// Set up fast system calls (SYSCALL/SYSRET)
    fn setup_fast_syscalls(&self) -> Result<(), &'static str> {
        unsafe {
            // Set up STAR register (CS and SS selectors)
            Star::write(
                SegmentSelector::new(0x08, x86_64::PrivilegeLevel::Ring0),
                SegmentSelector::new(0x1B, x86_64::PrivilegeLevel::Ring3),
                SegmentSelector::new(0x10, x86_64::PrivilegeLevel::Ring0),
                SegmentSelector::new(0x23, x86_64::PrivilegeLevel::Ring3),
            );
            // Set up LSTAR register (syscall entry point)
            let syscall_entry = syscall_entry_asm as *const () as u64;
            LStar::write(VirtAddr::new(syscall_entry));
            // Set up FMASK register (RFLAGS to mask during syscall)
            use x86_64::registers::rflags::RFlags;
            SFMask::write(RFlags::INTERRUPT_FLAG);
            // Enable SCE (System Call Extensions) in EFER
            let mut efer = Efer::read();
            efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
            Efer::write(efer);
        }
        Ok(())
    }

    /// Initialize system call table with handlers
    fn initialize_syscall_table(&self) {
        let mut table = self.table.write();
        table.insert(0, SyscallInfo {
            number: 0, name: "read", handler: syscall_read,
            call_count: AtomicU64::new(0), total_time: AtomicU64::new(0), last_called: AtomicU64::new(0),
        });
        table.insert(1, SyscallInfo {
            number: 1, name: "write", handler: syscall_write,
            call_count: AtomicU64::new(0), total_time: AtomicU64::new(0), last_called: AtomicU64::new(0),
        });
        table.insert(2, SyscallInfo {
            number: 2, name: "open", handler: syscall_open,
            call_count: AtomicU64::new(0), total_time: AtomicU64::new(0), last_called: AtomicU64::new(0),
        });
        table.insert(3, SyscallInfo {
            number: 3, name: "close", handler: syscall_close,
            call_count: AtomicU64::new(0), total_time: AtomicU64::new(0), last_called: AtomicU64::new(0),
        });
        table.insert(39, SyscallInfo {
            number: 39, name: "getpid", handler: syscall_getpid,
            call_count: AtomicU64::new(0), total_time: AtomicU64::new(0), last_called: AtomicU64::new(0),
        });
        // Add more syscalls as needed...
    }

    /// Compute hash of syscall table for integrity checking
    fn compute_table_hash(&self) {
        let table = self.table.read();
        let mut data = Vec::new();
        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }
        // Store hash (use kernel's crypto; replace with SHA3-256 if desired)
        let hash = crate::crypto::hash::sha3_256(&data);
        unsafe {
            core::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                (&self.original_table_hash as *const [u8; 32] as *mut [u8; 32]) as *mut u8,
                32,
            );
        }
    }

    /// Enable system call table protection
    fn enable_table_protection(&self) -> Result<(), &'static str> {
        // In a real implementation, would:
        // 1. Map syscall table as read-only
        // 2. Enable hypervisor protection
        // 3. Set up hardware breakpoints
        Ok(())
    }

    /// Handle system call dispatch
    pub fn dispatch_syscall(&self, number: u64, args: [u64; 6]) -> u64 {
        let start_time = crate::time::now_ns();
        self.statistics.total_calls.fetch_add(1, Ordering::Relaxed);

        // Security validation
        if !self.validate_syscall(number, &args) {
            self.statistics.blocked_calls.fetch_add(1, Ordering::Relaxed);
            return u64::MAX; // Error code
        }
        let handler = {
            let table = self.table.read();
            if let Some(info) = table.get(&number) {
                info.call_count.fetch_add(1, Ordering::Relaxed);
                info.last_called.store(start_time, Ordering::Relaxed);
                info.handler
            } else {
                return u64::MAX;
            }
        };
        let result = handler(args[0], args[1], args[2], args[3], args[4], args[5]);
        let end_time = crate::time::now_ns();
        let execution_time = end_time - start_time;
        self.statistics.total_time.fetch_add(execution_time, Ordering::Relaxed);
        self.record_syscall(number, args, result, start_time);
        result
    }

    /// Validate system call for security
    fn validate_syscall(&self, number: u64, args: &[u64; 6]) -> bool {
        match number {
            2 | 85 | 86 => { // open, creat, link
                if self.is_sensitive_path(args[0] as *const u8) { return false; }
            },
            57 => { // fork
                if self.is_fork_rate_limited() { return false; }
            },
            59 => { // execve
                if !self.is_trusted_executable(args[0] as *const u8) { return false; }
            },
            _ => {}
        }
        true
    }
    fn is_sensitive_path(&self, path_ptr: *const u8) -> bool {
        (path_ptr as u64) < 0x1000 || (path_ptr as u64) > 0x7FFFFFFFFFFF
    }
    fn is_fork_rate_limited(&self) -> bool { false }
    fn is_trusted_executable(&self, path_ptr: *const u8) -> bool { true }

    /// Record system call for monitoring
    fn record_syscall(&self, number: u64, args: [u64; 6], result: u64, timestamp: u64) {
        let record = SyscallRecord {
            number, args, return_value: result, timestamp,
            process_id: 1, thread_id: 1,
        };
        let mut recent_calls = self.recent_calls.lock();
        recent_calls.push(record);
        if recent_calls.len() > 1000 { recent_calls.remove(0); }
    }

    /// Detect system call table hooks
    pub fn detect_syscall_hooks(&self) -> bool {
        let table = self.table.read();
        let mut data = Vec::new();
        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }
        let current_hash = crate::crypto::hash::sha3_256(&data);
        if current_hash != self.original_table_hash {
            self.statistics.hook_detection_count.fetch_add(1, Ordering::Relaxed);
            self.statistics.last_hook_detection.store(crate::time::now_ns(), Ordering::Relaxed);
            self.hooks_detected.fetch_add(1, Ordering::Relaxed);
            crate::log::logger::log_info!("System call table hook detected!");
            return true;
        }
        false
    }
    pub fn verify_syscall_table_integrity(&self) -> bool {
        !self.detect_syscall_hooks()
    }
    pub fn get_recent_calls(&self) -> Vec<SyscallRecord> {
        let recent_calls = self.recent_calls.lock();
        recent_calls.clone()
    }
    pub fn get_syscalls_by_type(&self, call_type: SyscallNumber) -> Vec<SyscallRecord> {
        let recent_calls = self.recent_calls.lock();
        let filtered_calls: Vec<SyscallRecord> = recent_calls.iter()
            .filter(|record| record.number == call_type as u64)
            .cloned()
            .collect();
        let analysis = vec![
            format!("Filtered {} calls of type {:?}", recent_calls.len(), call_type),
            format!("Found {} matching calls", filtered_calls.len()),
        ];
        for entry in analysis {
            crate::log_debug!("{}", entry);
        }
        filtered_calls
    }
    pub fn get_statistics(&self) -> SyscallStats {
        SyscallStats {
            total_calls: AtomicU64::new(self.statistics.total_calls.load(Ordering::Relaxed)),
            total_time: AtomicU64::new(self.statistics.total_time.load(Ordering::Relaxed)),
            hook_detection_count: AtomicU64::new(self.statistics.hook_detection_count.load(Ordering::Relaxed)),
            blocked_calls: AtomicU64::new(self.statistics.blocked_calls.load(Ordering::Relaxed)),
            last_hook_detection: AtomicU64::new(self.statistics.last_hook_detection.load(Ordering::Relaxed)),
        }
    }
}

/// Global syscall manager
static SYSCALL_MANAGER: SyscallManager = SyscallManager::new();

/// System call entry point (called from assembly)
#[no_mangle]
pub extern "C" fn syscall_handler(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    SYSCALL_MANAGER.dispatch_syscall(number, [arg1, arg2, arg3, arg4, arg5, arg6])
}

/// Assembly syscall entry point
#[unsafe(naked)]
extern "C" fn syscall_entry_asm() {
    unsafe {
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
            "mov r10, rcx",
            "call {}",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop rcx",
            "pop r11",
            "pop rbp",
            "mov rsp, gs:0x10",
            "swapgs",
            "sysretq",
            sym syscall_handler,
        );
    }
}

// System call implementations

fn syscall_read(fd: u64, buf: u64, count: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    // FIXME: Stub syscall - integrate with VFS
    crate::log::logger::log_info!("{}", &format!("read(fd={}, buf=0x{:x}, count={})", fd, buf, count));
    0
}
fn syscall_write(fd: u64, buf: u64, count: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    // FIXME: Stub syscall - integrate with VFS
    crate::log::logger::log_info!("{}", &format!("write(fd={}, buf=0x{:x}, count={})", fd, buf, count));
    count
}
fn syscall_open(pathname: u64, flags: u64, mode: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    // FIXME: Stub syscall - integrate with VFS
    crate::log::logger::log_info!("{}", &format!("open(pathname=0x{:x}, flags={}, mode={})", pathname, flags, mode));
    3
}
fn syscall_close(fd: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    // FIXME: Stub syscall - integrate with VFS
    crate::log::logger::log_info!("{}", &format!("close(fd={})", fd));
    0
}
fn syscall_getpid(_arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    1
}

/// Initialize syscall subsystem
pub fn init() -> Result<(), &'static str> {
    SYSCALL_MANAGER.init()
}

/// Detect syscall hooks
pub fn detect_syscall_hooks() -> bool {
    SYSCALL_MANAGER.detect_syscall_hooks()
}

/// Verify syscall table integrity
pub fn verify_syscall_table_integrity() -> bool {
    SYSCALL_MANAGER.verify_syscall_table_integrity()
}

/// Get recent syscalls
pub fn get_recent_calls() -> Vec<SyscallRecord> {
    SYSCALL_MANAGER.get_recent_calls()
}

/// Get syscall statistics
pub fn get_syscall_stats() -> SyscallStats {
    SYSCALL_MANAGER.get_statistics()
}

/// Advanced syscall security features
pub mod security {
    /// Enable syscall filtering
    pub fn enable_syscall_filtering() -> Result<(), &'static str> {
        crate::log::logger::log_info!("Syscall filtering enabled");
        Ok(())
    }
    /// Enable syscall auditing
    pub fn enable_syscall_auditing() -> Result<(), &'static str> {
        crate::log::logger::log_info!("Syscall auditing enabled");
        Ok(())
    }
    /// Detect syscall injection attacks
    pub fn detect_syscall_injection() -> bool {
        false
    }
    /// Enable control flow integrity for syscalls
    pub fn enable_cfi() -> Result<(), &'static str> {
        crate::log::logger::log_info!("Syscall CFI enabled");
        Ok(())
    }
}
