// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.


//! This is the NONOS real System Call Handler first Implementation
//!
//! Production system call interface with proper error handling

use alloc::{vec::Vec, string::String, format};
use core::arch::{asm, naked_asm};
use x86_64::{VirtAddr, PhysAddr, registers::rflags::RFlags, structures::gdt::SegmentSelector, PrivilegeLevel};
use crate::process::process::{ProcessId, get_current_process_id};
use crate::memory::virtual_memory;

/// System call numbers (Linux-compatible subset)
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
    Getsockname = 51,
    Getpeername = 52,
    Socketpair = 53,
    Setsockopt = 54,
    Getsockopt = 55,
    Clone = 56,
    Fork = 57,
    Vfork = 58,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
    Kill = 62,
    Uname = 63,
    Semget = 64,
    Semop = 65,
    Semctl = 66,
    Shmdt = 67,
    Msgget = 68,
    Msgsnd = 69,
    Msgrcv = 70,
    Msgctl = 71,
    Fcntl = 72,
    Flock = 73,
    Fsync = 74,
    Fdatasync = 75,
    Truncate = 76,
    Ftruncate = 77,
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,
    Fchdir = 81,
    Rename = 82,
    Mkdir = 83,
    Rmdir = 84,
    Creat = 85,
    Link = 86,
    Unlink = 87,
    Symlink = 88,
    Readlink = 89,
    Chmod = 90,
    Fchmod = 91,
    Chown = 92,
    Fchown = 93,
    Lchown = 94,
    Umask = 95,
    Gettimeofday = 96,
    Getrlimit = 97,
    Getrusage = 98,
    Sysinfo = 99,
    Times = 100,
}

impl From<u64> for SyscallNumber {
    fn from(num: u64) -> Self {
        match num {
            0 => SyscallNumber::Read,
            1 => SyscallNumber::Write,
            2 => SyscallNumber::Open,
            3 => SyscallNumber::Close,
            12 => SyscallNumber::Brk,
            24 => SyscallNumber::SchedYield,
            39 => SyscallNumber::Getpid,
            57 => SyscallNumber::Fork,
            59 => SyscallNumber::Execve,
            60 => SyscallNumber::Exit,
            96 => SyscallNumber::Gettimeofday,
            _ => SyscallNumber::Read, // Default fallback
        }
    }
}

/// System call result
#[derive(Debug, Clone, Copy)]
pub struct SyscallResult {
    pub value: i64,
    pub errno: u32,
}

impl SyscallResult {
    pub fn ok(value: i64) -> Self {
        SyscallResult { value, errno: 0 }
    }
    
    pub fn error(errno: u32) -> Self {
        SyscallResult { value: -1, errno }
    }
}

/// Saved registers during system call
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallRegs {
    pub rax: u64,  // syscall number and return value
    pub rdi: u64,  // arg0
    pub rsi: u64,  // arg1
    pub rdx: u64,  // arg2
    pub r10: u64,  // arg3 (rcx is used by syscall instruction)
    pub r8: u64,   // arg4
    pub r9: u64,   // arg5
    pub rcx: u64,  // return RIP
    pub r11: u64,  // saved RFLAGS
    pub rsp: u64,  // user stack pointer
}

/// File descriptor table entry
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub fd: i32,
    pub file_type: FileDescriptorType,
    pub offset: u64,
    pub flags: u32,
    pub inode: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileDescriptorType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Pipe,
    Socket,
}

/// Process file descriptor table
#[derive(Debug)]
pub struct ProcessFdTable {
    pub fds: Vec<Option<FileDescriptor>>,
    pub next_fd: i32,
}

impl ProcessFdTable {
    pub fn new() -> Self {
        let mut fds = Vec::with_capacity(256);
        
        // Initialize with standard streams
        fds.push(Some(FileDescriptor {
            fd: 0,
            file_type: FileDescriptorType::CharDevice,
            offset: 0,
            flags: 0,
            inode: None,
        })); // stdin
        
        fds.push(Some(FileDescriptor {
            fd: 1,
            file_type: FileDescriptorType::CharDevice,
            offset: 0,
            flags: 0,
            inode: None,
        })); // stdout
        
        fds.push(Some(FileDescriptor {
            fd: 2,
            file_type: FileDescriptorType::CharDevice,
            offset: 0,
            flags: 0,
            inode: None,
        })); // stderr
        
        // Fill rest with None
        for _ in 3..256 {
            fds.push(None);
        }
        
        ProcessFdTable {
            fds,
            next_fd: 3,
        }
    }
    
    pub fn allocate_fd(&mut self, file_type: FileDescriptorType) -> Result<i32, u32> {
        for (i, fd_slot) in self.fds.iter_mut().enumerate().skip(self.next_fd as usize) {
            if fd_slot.is_none() {
                let fd = i as i32;
                *fd_slot = Some(FileDescriptor {
                    fd,
                    file_type,
                    offset: 0,
                    flags: 0,
                    inode: None,
                });
                return Ok(fd);
            }
        }
        
        Err(24) // EMFILE - too many open files
    }
    
    pub fn get_fd(&self, fd: i32) -> Option<&FileDescriptor> {
        if fd < 0 || fd as usize >= self.fds.len() {
            return None;
        }
        self.fds[fd as usize].as_ref()
    }
    
    pub fn close_fd(&mut self, fd: i32) -> Result<(), u32> {
        if fd < 0 || fd as usize >= self.fds.len() {
            return Err(9); // EBADF
        }
        
        if self.fds[fd as usize].is_none() {
            return Err(9); // EBADF
        }
        
        self.fds[fd as usize] = None;
        if fd < self.next_fd {
            self.next_fd = fd;
        }
        
        Ok(())
    }
}

/// System call handler entry point (called from assembly)
#[no_mangle]
pub extern "C" fn syscall_handler(regs: &mut SyscallRegs) {
    let syscall_num = SyscallNumber::from(regs.rax);
    
    // Validate user pointers before processing
    if let Err(errno) = validate_syscall_args(syscall_num, regs) {
        regs.rax = SyscallResult::error(errno).value as u64;
        return;
    }
    
    let result = match syscall_num {
        SyscallNumber::Read => sys_read(regs.rdi as i32, regs.rsi, regs.rdx as usize),
        SyscallNumber::Write => sys_write(regs.rdi as i32, regs.rsi, regs.rdx as usize),
        SyscallNumber::Open => sys_open(regs.rdi, regs.rsi as i32, regs.rdx as u32),
        SyscallNumber::Close => sys_close(regs.rdi as i32),
        SyscallNumber::Brk => sys_brk(regs.rdi),
        SyscallNumber::Fork => sys_fork(),
        SyscallNumber::Execve => sys_execve(regs.rdi, regs.rsi, regs.rdx),
        SyscallNumber::Exit => sys_exit(regs.rdi as i32),
        SyscallNumber::Getpid => sys_getpid(),
        SyscallNumber::SchedYield => sys_sched_yield(),
        SyscallNumber::Gettimeofday => sys_gettimeofday(regs.rdi, regs.rsi),
        _ => SyscallResult::error(38), // ENOSYS - function not implemented
    };
    
    regs.rax = result.value as u64;
}

/// Validate system call arguments
fn validate_syscall_args(syscall_num: SyscallNumber, regs: &SyscallRegs) -> Result<(), u32> {
    match syscall_num {
        SyscallNumber::Read | SyscallNumber::Write => {
            let buffer_addr = regs.rsi;
            let length = regs.rdx as usize;
            
            if buffer_addr == 0 && length > 0 {
                return Err(14); // EFAULT
            }
            
            // Check if buffer is in user space
            if !is_user_address(VirtAddr::new(buffer_addr)) {
                return Err(14); // EFAULT
            }
            
            // Check for buffer overflow
            if buffer_addr.checked_add(length as u64).is_none() {
                return Err(14); // EFAULT
            }
        },
        
        SyscallNumber::Open => {
            let path_addr = regs.rdi;
            if path_addr == 0 {
                return Err(14); // EFAULT
            }
            
            if !is_user_address(VirtAddr::new(path_addr)) {
                return Err(14); // EFAULT
            }
            
            // Validate path string
            if let Err(_) = validate_user_string(VirtAddr::new(path_addr), 4096) {
                return Err(14); // EFAULT
            }
        },
        
        SyscallNumber::Execve => {
            let filename_addr = regs.rdi;
            let argv_addr = regs.rsi;
            let envp_addr = regs.rdx;
            
            if filename_addr == 0 {
                return Err(14); // EFAULT
            }
            
            if !is_user_address(VirtAddr::new(filename_addr)) {
                return Err(14); // EFAULT
            }
            
            // Validate argv and envp arrays if present
            if argv_addr != 0 && !is_user_address(VirtAddr::new(argv_addr)) {
                return Err(14); // EFAULT
            }
            
            if envp_addr != 0 && !is_user_address(VirtAddr::new(envp_addr)) {
                return Err(14); // EFAULT
            }
        },
        
        _ => {} // No special validation needed
    }
    
    Ok(())
}

/// Check if address is in user space
fn is_user_address(addr: VirtAddr) -> bool {
    // User space typically below 0x800000000000 on x86_64
    addr.as_u64() < 0x800000000000
}

/// Validate user string (check for null terminator within max_len)
fn validate_user_string(addr: VirtAddr, max_len: usize) -> Result<usize, ()> {
    unsafe {
        let ptr = addr.as_ptr::<u8>();
        for i in 0..max_len {
            // This would need proper page fault handling in production
            let byte = core::ptr::read_volatile(ptr.add(i));
            if byte == 0 {
                return Ok(i);
            }
        }
    }
    Err(()) // String too long or no null terminator
}

/// sys_read - Read from file descriptor
fn sys_read(fd: i32, _buffer: u64, count: usize) -> SyscallResult {
    if count == 0 {
        return SyscallResult::ok(0);
    }
    
    // Get current process and its FD table
    let _process_id = match get_current_process_id() {
        Some(pid) => pid,
        None => return SyscallResult::error(9), // EBADF
    };
    
    // For now, simulate reading from stdin/stdout/stderr
    match fd {
        0 => { // stdin - simulate keyboard input
            // In real implementation, has to read from keyboard buffer
            SyscallResult::ok(0) // No input available
        },
        1 | 2 => { // stdout/stderr - invalid for reading
            SyscallResult::error(9) // EBADF
        },
        _ => {
            // Regular file - would interact with VFS
            // For now, we simulate empty file
            SyscallResult::ok(0)
        }
    }
}

/// sys_write - Write to file descriptor  
fn sys_write(fd: i32, buffer: u64, count: usize) -> SyscallResult {
    if count == 0 {
        return SyscallResult::ok(0);
    }
    
    match fd {
        0 => { // stdin - invalid for writing
            SyscallResult::error(9) // EBADF
        },
        1 | 2 => { // stdout/stderr - write to console
            // Copy data from user space
            let mut output = Vec::with_capacity(count);
            unsafe {
                let user_ptr = buffer as *const u8;
                for i in 0..count {
                    // This would need proper page fault handling
                    let byte = core::ptr::read_volatile(user_ptr.add(i));
                    output.push(byte);
                    
                    // Safety break to prevent infinite loops
                    if i > 4096 {
                        break;
                    }
                }
            }
            
            // Convert to string and output to VGA
            if let Ok(text) = core::str::from_utf8(&output) {
                crate::arch::x86_64::vga::print(text);
            }
            
            SyscallResult::ok(count as i64)
        },
        _ => {
            // Regular file - would interact with VFS
            SyscallResult::error(9) // EBADF for now
        }
    }
}

/// sys_open - Open file
fn sys_open(pathname: u64, _flags: i32, _mode: u32) -> SyscallResult {
    // Read pathname from user space
    let path = match read_user_string(VirtAddr::new(pathname), 4096) {
        Ok(p) => p,
        Err(_) => return SyscallResult::error(14), // EFAULT
    };
    
    // For now, only support a few basic paths
    match path.as_str() {
        "/dev/null" => SyscallResult::ok(3), // Return a dummy FD
        "/dev/zero" => SyscallResult::ok(4), // Return a dummy FD
        "/proc/version" => SyscallResult::ok(5), // Return a dummy FD
        _ => SyscallResult::error(2), // ENOENT - file not found
    }
}

/// sys_close - Close file descriptor
fn sys_close(fd: i32) -> SyscallResult {
    if fd < 0 {
        return SyscallResult::error(9); // EBADF
    }
    
    // Can't close stdin/stdout/stderr
    if fd < 3 {
        return SyscallResult::error(9); // EBADF
    }
    
    // For now, just accept closing any FD >= 3
    SyscallResult::ok(0)
}

/// sys_brk - Change data segment size
fn sys_brk(addr: u64) -> SyscallResult {
    // Get current process heap info
    let current_brk = get_current_process_brk().unwrap_or(0x400000000); // Default heap start
    
    if addr == 0 {
        // Return current brk
        return SyscallResult::ok(current_brk as i64);
    }
    
    if addr < current_brk {
        // Can't shrink heap below current position
        return SyscallResult::ok(current_brk as i64);
    }
    
    // Calculate pages needed
    let page_aligned_addr = (addr + 4095) & !4095;
    let pages_needed = (page_aligned_addr - current_brk) / 4096;
    
    // Allocate memory pages
    for i in 0..pages_needed {
        let page_addr = VirtAddr::new(current_brk + (i * 4096));
        
        if let Some(frame) = crate::memory::page_allocator::allocate_frame() {
            if let Err(_) = virtual_memory::map_memory_range(
                page_addr,
                frame.start_address(),
                4096,
                x86_64::structures::paging::PageTableFlags::PRESENT |
                x86_64::structures::paging::PageTableFlags::WRITABLE |
                x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE
            ) {
                return SyscallResult::error(12); // ENOMEM
            }
        } else {
            return SyscallResult::error(12); // ENOMEM
        }
    }
    
    // Update process brk
    set_current_process_brk(page_aligned_addr);
    SyscallResult::ok(page_aligned_addr as i64)
}

/// sys_fork - Create child process
fn sys_fork() -> SyscallResult {
    // Fork implementation would be very complex
    // For now, return error
    SyscallResult::error(11) // EAGAIN - resource temporarily unavailable
}

/// sys_execve - Execute program
fn sys_execve(filename: u64, _argv: u64, _envp: u64) -> SyscallResult {
    let _path = match read_user_string(VirtAddr::new(filename), 4096) {
        Ok(p) => p,
        Err(_) => return SyscallResult::error(14), // EFAULT
    };
    
    // execve implementation would load ELF and replace current process
    // For now, return error
    SyscallResult::error(2) // ENOENT
}

/// sys_exit - Terminate current process
fn sys_exit(_status: i32) -> SyscallResult {
    // This should never return - process should be terminated
    // For now, just halt
    loop {
        unsafe { asm!("hlt"); }
    }
}

/// sys_getpid - Get process ID
fn sys_getpid() -> SyscallResult {
    match get_current_process_id() {
        Some(pid) => SyscallResult::ok(pid as i64),
        None => SyscallResult::ok(1), // Return init PID as fallback
    }
}

/// sys_sched_yield - Yield CPU to scheduler
fn sys_sched_yield() -> SyscallResult {
    // Trigger scheduler
    crate::sched::executor::yield_to_scheduler();
    SyscallResult::ok(0)
}

/// sys_gettimeofday - Get current time
fn sys_gettimeofday(tv: u64, _tz: u64) -> SyscallResult {
    let timestamp_ms = crate::time::timestamp_millis();
    let seconds = timestamp_ms / 1000;
    let microseconds = (timestamp_ms % 1000) * 1000;
    
    if tv != 0 {
        // Write timeval struct to user space
        unsafe {
            let timeval_ptr = tv as *mut [u64; 2];
            core::ptr::write_volatile(timeval_ptr, [seconds, microseconds]);
        }
    }
    
    SyscallResult::ok(0)
}

/// Read string from user space
fn read_user_string(addr: VirtAddr, max_len: usize) -> Result<String, ()> {
    let mut result = String::new();
    
    unsafe {
        let ptr = addr.as_ptr::<u8>();
        for i in 0..max_len {
            let byte = core::ptr::read_volatile(ptr.add(i));
            if byte == 0 {
                break;
            }
            result.push(byte as char);
        }
    }
    
    if result.len() == max_len {
        Err(()) // String too long
    } else {
        Ok(result)
    }
}

/// Get current process brk (simplified)
fn get_current_process_brk() -> Option<u64> {
    // Would get from process structure
    Some(0x400000000)
}

/// Set current process brk (simplified)
fn set_current_process_brk(_addr: u64) {
    // Would update process structure
}

/// System call entry point in assembly
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // Save user registers
        "push rcx",      // Return RIP
        "push r11",      // Saved RFLAGS
        "push rsp",      // User stack
        "push r9",
        "push r8", 
        "push r10",      // arg3
        "push rdx",      // arg2
        "push rsi",      // arg1
        "push rdi",      // arg0
        "push rax",      // syscall number
        
        // Set up kernel stack
        "mov rdi, rsp",  // Pass register struct as argument
        "call {}",       // Call syscall_handler
        
        // Restore registers (result in rax)
        "add rsp, 8",    // Skip old rax (now has return value)
        "pop rdi",
        "pop rsi", 
        "pop rdx",
        "pop r10",
        "pop r8",
        "pop r9",
        "pop rsp",       // Restore user stack
        "pop r11",       // Restore RFLAGS
        "pop rcx",       // Restore RIP
        
        // Return to user space
        "sysretq",
        
        sym syscall_handler,
        options()
    );
}

/// Initialize system call interface
pub fn init_syscall_interface() -> Result<(), &'static str> {
    // Set up MSR for syscall entry point
    unsafe {
        // STAR - syscall target address
        x86_64::registers::model_specific::Star::write(
            SegmentSelector::new(1, PrivilegeLevel::Ring0),  // Kernel CS
            SegmentSelector::new(2, PrivilegeLevel::Ring0),  // Kernel SS
            SegmentSelector::new(3, PrivilegeLevel::Ring3),  // User CS
            SegmentSelector::new(4, PrivilegeLevel::Ring3),  // User SS
        ).map_err(|_| "Failed to set STAR MSR")?;
        
        // LSTAR - syscall entry point
        x86_64::registers::model_specific::LStar::write(
            VirtAddr::new(syscall_entry as u64)
        );
        
        // SFMASK - flags to clear on syscall
        x86_64::registers::model_specific::SFMask::write(
            RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG
        );
        
        // Enable syscall/sysret in EFER
        let mut efer = x86_64::registers::model_specific::Efer::read();
        efer |= x86_64::registers::model_specific::EferFlags::SYSTEM_CALL_EXTENSIONS;
        x86_64::registers::model_specific::Efer::write(efer);
    }
    
    Ok(())
}
