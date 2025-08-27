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

//! NONOS Syscall Interface
//! 
//! Production system call handling 

pub mod capabilities;
pub mod dispatch;
pub mod handler;
pub mod validation;
pub mod vdso;
pub mod nonos_syscall;

use crate::syscall::capabilities::CapabilityToken;

/// System call numbers for NONOS
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

/// Syscall result with capability validation
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
    // Would check current task's capability token
    // For now, allow basic operations
    match syscall {
        SyscallNumber::Exit | SyscallNumber::Read | SyscallNumber::Write => true,
        SyscallNumber::ModuleLoad | SyscallNumber::CryptoOp => {
            // Would require advanced capabilities
            false
        }
        _ => true,
    }
}
