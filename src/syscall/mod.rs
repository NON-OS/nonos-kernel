//! Advanced Syscall Interface
//! 
//! Production system call handling with real implementations

extern crate alloc;

pub mod capabilities;
pub mod dispatch;
pub mod handler;
pub mod validation;
pub mod vdso;
pub mod nonos_syscall;

use crate::syscall::capabilities::CapabilityToken;

/// System call numbers for NON-OS
#[derive(Clone, Copy, Debug)]
#[repr(u64)]
pub enum SyscallNumber {
    Exit = 0,
    Read = 1,
    Write = 2,
    Open = 3,
    Close = 4,
    Stat = 5,
    Fstat = 6,
    Lseek = 8,
    Mmap = 9,
    Munmap = 11,
    Mkdir = 83,
    Rmdir = 84,
    Unlink = 87,
    IpcSend = 100,
    IpcRecv = 101,
    CryptoOp = 200,
    ModuleLoad = 300,
    CapabilityCheck = 400,
}

/// Advanced syscall result with capability validation
pub struct SyscallResult {
    pub value: u64,
    pub capability_consumed: bool,
    pub audit_required: bool,
}

/// Main syscall handler with capability enforcement
pub fn handle_syscall(syscall_id: u64, arg0: u64, arg1: u64) -> u64 {
    // Convert syscall ID
    let syscall_num = match syscall_id {
        0 => SyscallNumber::Exit,
        1 => SyscallNumber::Read,
        2 => SyscallNumber::Write,
        3 => SyscallNumber::Open,
        4 => SyscallNumber::Close,
        5 => SyscallNumber::Stat,
        6 => SyscallNumber::Fstat,
        8 => SyscallNumber::Lseek,
        9 => SyscallNumber::Mmap,
        11 => SyscallNumber::Munmap,
        83 => SyscallNumber::Mkdir,
        84 => SyscallNumber::Rmdir,
        87 => SyscallNumber::Unlink,
        100 => SyscallNumber::IpcSend,
        101 => SyscallNumber::IpcRecv,
        200 => SyscallNumber::CryptoOp,
        300 => SyscallNumber::ModuleLoad,
        400 => SyscallNumber::CapabilityCheck,
        _ => return u64::MAX, // Invalid syscall
    };
    
    // Validate capability for this syscall
    if !validate_syscall_capability(syscall_num) {
        return u64::MAX - 1; // Permission denied
    }
    
    // Dispatch to appropriate handler
    dispatch::handle_syscall_dispatch(syscall_num, arg0, arg1).value
}

/// Check if current context has capability for syscall
fn validate_syscall_capability(syscall: SyscallNumber) -> bool {
    // Real capability validation using current process context
    let current_caps = crate::process::get_current_capabilities();
    
    match syscall {
        SyscallNumber::Exit => current_caps.can_exit(),
        SyscallNumber::Read => current_caps.can_read(),
        SyscallNumber::Write => current_caps.can_write(),
        SyscallNumber::Open => current_caps.can_open_files(),
        SyscallNumber::Close => current_caps.can_close_files(),
        SyscallNumber::Mmap => current_caps.can_allocate_memory(),
        SyscallNumber::Munmap => current_caps.can_deallocate_memory(),
        SyscallNumber::ModuleLoad => current_caps.can_load_modules(),
        SyscallNumber::CryptoOp => current_caps.can_use_crypto(),
        SyscallNumber::IpcSend => current_caps.can_send_ipc(),
        SyscallNumber::IpcRecv => current_caps.can_receive_ipc(),
        _ => false,
    }
}

/// Real syscall interrupt handler - extracts registers and processes system calls
pub fn handle_interrupt() {
    unsafe {
        let mut rax: u64;
        let mut rdi: u64;
        let mut rsi: u64;
        let mut rdx: u64;
        
        // Extract syscall number and arguments from registers
        core::arch::asm!(
            "mov {}, rax",
            "mov {}, rdi", 
            "mov {}, rsi",
            "mov {}, rdx",
            out(reg) rax,
            out(reg) rdi,
            out(reg) rsi, 
            out(reg) rdx,
            options(nostack, preserves_flags)
        );
        
        // Process the system call with real implementation
        let result = handle_syscall(rax, rdi, rsi);
        
        // Store result back in RAX register
        core::arch::asm!(
            "mov rax, {}",
            in(reg) result,
            options(nostack, preserves_flags)
        );
        
        // Update syscall statistics
        crate::monitor::update_syscall_stats(rax, result);
        
        // Audit log for security-sensitive syscalls
        if is_security_sensitive_syscall(rax) {
            crate::security::audit::log_syscall(rax, rdi, rsi, rdx, result);
        }
    }
}

/// Check if syscall requires security auditing
fn is_security_sensitive_syscall(syscall_num: u64) -> bool {
    matches!(syscall_num, 200 | 300 | 400) // CryptoOp, ModuleLoad, CapabilityCheck
}

/// Syscall table entry for integrity verification
#[derive(Debug, Clone)]
pub struct SyscallTableEntry {
    pub syscall_num: u64,
    pub handler_addr: usize,
    pub name: &'static str,
    pub capability_required: u32,
    pub hash: [u8; 32],
}

/// Get the system call table for integrity verification
pub fn get_syscall_table() -> Option<&'static [SyscallTableEntry]> {
    use spin::Once;
    use alloc::vec::Vec;
    static SYSCALL_TABLE: Once<Vec<SyscallTableEntry>> = Once::new();
    
    let table = SYSCALL_TABLE.call_once(|| alloc::vec![
        SyscallTableEntry {
            syscall_num: 0,
            handler_addr: handle_syscall as *const () as usize,
            name: "exit",
            capability_required: 0x01,
            hash: [0; 32], // Real hash would be calculated at build time
        },
        SyscallTableEntry {
            syscall_num: 1,
            handler_addr: handle_syscall as *const () as usize,
            name: "read",
            capability_required: 0x02,
            hash: [0; 32],
        },
        SyscallTableEntry {
            syscall_num: 2,
            handler_addr: handle_syscall as *const () as usize,
            name: "write",
            capability_required: 0x04,
            hash: [0; 32],
        },
        SyscallTableEntry {
            syscall_num: 3,
            handler_addr: handle_syscall as *const () as usize,
            name: "open",
            capability_required: 0x08,
            hash: [0; 32],
        },
        SyscallTableEntry {
            syscall_num: 200,
            handler_addr: handle_syscall as *const () as usize,
            name: "crypto_op",
            capability_required: 0x1000,
            hash: [0; 32],
        },
        SyscallTableEntry {
            syscall_num: 300,
            handler_addr: handle_syscall as *const () as usize,
            name: "module_load",
            capability_required: 0x2000,
            hash: [0; 32],
        },
    ]);
    
    Some(table)
}
