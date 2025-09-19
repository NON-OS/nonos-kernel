//! Advanced Syscall Dispatch System
//! 
//! High-performance syscall routing with per-call instrumentation

use super::{SyscallNumber, SyscallResult};
use alloc::format;

/// Advanced syscall dispatcher with performance tracking
pub fn handle_syscall_dispatch(syscall: SyscallNumber, arg0: u64, arg1: u64) -> SyscallResult {
    // Record syscall entry for performance analysis
    let start_time = crate::arch::x86_64::time::timer::now_ns();
    
    let result = match syscall {
        SyscallNumber::Exit => handle_exit(arg0),
        SyscallNumber::Read => handle_read(arg0, arg1),
        SyscallNumber::Write => handle_write(arg0, arg1),
        SyscallNumber::Open => handle_open(arg0, arg1),
        SyscallNumber::Close => handle_close(arg0),
        SyscallNumber::Stat => handle_stat(arg0, arg1),
        SyscallNumber::Fstat => handle_fstat(arg0, arg1),
        SyscallNumber::Lseek => handle_lseek(arg0, arg1),
        SyscallNumber::Mkdir => handle_mkdir(arg0, arg1),
        SyscallNumber::Rmdir => handle_rmdir(arg0),
        SyscallNumber::Unlink => handle_unlink(arg0),
        SyscallNumber::Mmap => handle_mmap(arg0, arg1),
        SyscallNumber::Munmap => handle_munmap(arg0, arg1),
        SyscallNumber::IpcSend => handle_ipc_send(arg0, arg1),
        SyscallNumber::IpcRecv => handle_ipc_recv(arg0, arg1),
        SyscallNumber::CryptoOp => handle_crypto_op(arg0, arg1),
        SyscallNumber::ModuleLoad => handle_module_load(arg0, arg1),
        SyscallNumber::CapabilityCheck => handle_capability_check(arg0, arg1),
    };
    
    // Record completion time for telemetry
    let end_time = crate::arch::x86_64::time::timer::now_ns();
    log_syscall_performance(syscall, start_time, end_time);
    
    result
}

// Individual syscall handlers
fn handle_exit(_code: u64) -> SyscallResult {
    // Would terminate current task
    SyscallResult {
        value: 0,
        capability_consumed: false,
        audit_required: true,
    }
}

fn handle_read(fd: u64, buf_and_len: u64) -> SyscallResult {
    // N0N-OS read interface: fd, (buffer_ptr | length << 32)
    let buf_ptr = buf_and_len & 0xFFFFFFFF;
    let length = (buf_and_len >> 32) & 0xFFFFFFFF;
    
    if buf_ptr == 0 || length == 0 || length > 1048576 { // Max 1MB reads
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    // Get VFS and read from file
    if let Some(vfs) = crate::fs::get_vfs() {
        unsafe {
            let buffer = core::slice::from_raw_parts_mut(buf_ptr as *mut u8, length as usize);
            
            match vfs.read_file(fd, 0, buffer) {
                Ok(bytes_read) => SyscallResult {
                    value: bytes_read as u64,
                    capability_consumed: true,
                    audit_required: false,
                },
                Err(_) => SyscallResult {
                    value: u64::MAX - 8, // -EBADF
                    capability_consumed: false,
                    audit_required: false,
                }
            }
        }
    } else {
        SyscallResult {
            value: u64::MAX - 2, // -ENOSYS
            capability_consumed: false,
            audit_required: false,
        }
    }
}

fn handle_write(fd: u64, buf_and_count: u64) -> SyscallResult {
    // N0N-OS syscall interface: extract buffer pointer and count from arg1
    // Upper 32 bits = count, lower 32 bits = buffer offset (or use other encoding)
    let buf_ptr = buf_and_count & 0xFFFFFFFF;
    let count = (buf_and_count >> 32) & 0xFFFFFFFF;
    if fd == 1 || fd == 2 {  // stdout or stderr
        // Validate user buffer pointer
        if buf_ptr == 0 || count == 0 || count > 4096 {  // Max 4KB writes
            return SyscallResult {
                value: u64::MAX,  // -EINVAL
                capability_consumed: false,
                audit_required: false,
            };
        }
        
        unsafe {
            let buffer = core::slice::from_raw_parts(buf_ptr as *const u8, count as usize);
            
            // Validate the buffer is readable memory (basic check)
            let _first_byte = unsafe { core::ptr::read_volatile(buffer.as_ptr()) };
            // TODO: Add proper page fault handling for invalid memory access
            
            // Write to serial console
            for &byte in buffer {
                crate::arch::x86_64::serial::write_byte(byte);
            }
            
            // Also write to VGA if available
            if let Ok(s) = core::str::from_utf8(buffer) {
                crate::arch::x86_64::vga::print(s);
            }
        }
        
        SyscallResult {
            value: count,  // Return number of bytes written
            capability_consumed: false,
            audit_required: false,
        }
    } else if fd == 0 {  // stdin
        SyscallResult {
            value: u64::MAX - 8,  // -EBADF (bad file descriptor)
            capability_consumed: false,
            audit_required: false,
        }
    } else {
        // Other file descriptors not supported yet
        SyscallResult {
            value: u64::MAX - 8,  // -EBADF  
            capability_consumed: true,
            audit_required: true,
        }
    }
}

fn handle_open(path_ptr: u64, _flags: u64) -> SyscallResult {
    // Basic path validation
    if path_ptr == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    // Get VFS reference
    if let Some(vfs) = crate::fs::get_vfs() {
        // Convert path pointer to string (simplified)
        unsafe {
            let path_str = core::ffi::CStr::from_ptr(path_ptr as *const i8);
            if let Ok(path) = path_str.to_str() {
                // Create file if it doesn't exist
                let mode = crate::fs::FileMode {
                    permissions: 0o644,
                    file_type: crate::fs::FileType::RegularFile,
                    setuid: false,
                    setgid: false,
                    sticky: false,
                };
                
                match vfs.create_file(path, mode) {
                    Ok(inode) => SyscallResult {
                        value: inode, // Return inode as file descriptor
                        capability_consumed: true,
                        audit_required: false,
                    },
                    Err(_) => {
                        // Try to resolve existing file
                        match vfs.resolve_path(path) {
                            Ok(inode) => SyscallResult {
                                value: inode,
                                capability_consumed: false,
                                audit_required: false,
                            },
                            Err(_) => SyscallResult {
                                value: u64::MAX - 1, // -ENOENT
                                capability_consumed: true,
                                audit_required: true,
                            }
                        }
                    }
                }
            } else {
                SyscallResult {
                    value: u64::MAX, // -EINVAL
                    capability_consumed: false,
                    audit_required: false,
                }
            }
        }
    } else {
        SyscallResult {
            value: u64::MAX - 2, // -ENOSYS
            capability_consumed: false,
            audit_required: true,
        }
    }
}

fn handle_close(_fd: u64) -> SyscallResult {
    SyscallResult {
        value: 0,
        capability_consumed: false,
        audit_required: false,
    }
}

fn handle_mmap(_addr: u64, _len: u64) -> SyscallResult {
    SyscallResult {
        value: u64::MAX,
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_munmap(_addr: u64, _len: u64) -> SyscallResult {
    SyscallResult {
        value: 0,
        capability_consumed: true,
        audit_required: false,
    }
}

fn handle_ipc_send(_target: u64, _msg: u64) -> SyscallResult {
    SyscallResult {
        value: u64::MAX,
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_ipc_recv(_source: u64, _buf: u64) -> SyscallResult {
    SyscallResult {
        value: u64::MAX,
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_crypto_op(_op: u64, _data: u64) -> SyscallResult {
    SyscallResult {
        value: u64::MAX,
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_module_load(_path: u64, _flags: u64) -> SyscallResult {
    SyscallResult {
        value: u64::MAX,
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_capability_check(_cap: u64, _flags: u64) -> SyscallResult {
    SyscallResult {
        value: 1, // Has capability
        capability_consumed: false,
        audit_required: false,
    }
}

fn handle_stat(path_ptr: u64, stat_buf: u64) -> SyscallResult {
    if path_ptr == 0 || stat_buf == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    if let Some(vfs) = crate::fs::get_vfs() {
        unsafe {
            let path_str = core::ffi::CStr::from_ptr(path_ptr as *const i8);
            if let Ok(path) = path_str.to_str() {
                match vfs.resolve_path(path) {
                    Ok(inode) => {
                        if let Some(vfs_inode) = vfs.get_inode(inode) {
                            let metadata = vfs_inode.metadata.read();
                            // Write stat information to user buffer
                            let stat_ptr = stat_buf as *mut u8;
                            let stat_data = [
                                metadata.inode.to_le_bytes(),
                                metadata.size.to_le_bytes(),
                                metadata.mtime.to_le_bytes(),
                            ].concat();
                            core::ptr::copy_nonoverlapping(stat_data.as_ptr(), stat_ptr, stat_data.len());
                            
                            SyscallResult {
                                value: 0, // Success
                                capability_consumed: false,
                                audit_required: false,
                            }
                        } else {
                            SyscallResult {
                                value: u64::MAX - 1, // -ENOENT
                                capability_consumed: false,
                                audit_required: false,
                            }
                        }
                    },
                    Err(_) => SyscallResult {
                        value: u64::MAX - 1, // -ENOENT
                        capability_consumed: false,
                        audit_required: false,
                    }
                }
            } else {
                SyscallResult {
                    value: u64::MAX, // -EINVAL
                    capability_consumed: false,
                    audit_required: false,
                }
            }
        }
    } else {
        SyscallResult {
            value: u64::MAX - 2, // -ENOSYS
            capability_consumed: false,
            audit_required: false,
        }
    }
}

fn handle_fstat(fd: u64, stat_buf: u64) -> SyscallResult {
    if stat_buf == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    if let Some(vfs) = crate::fs::get_vfs() {
        if let Some(vfs_inode) = vfs.get_inode(fd) {
            let metadata = vfs_inode.metadata.read();
            unsafe {
                let stat_ptr = stat_buf as *mut u8;
                let stat_data = [
                    metadata.inode.to_le_bytes(),
                    metadata.size.to_le_bytes(),
                    metadata.mtime.to_le_bytes(),
                ].concat();
                core::ptr::copy_nonoverlapping(stat_data.as_ptr(), stat_ptr, stat_data.len());
            }
            
            SyscallResult {
                value: 0, // Success
                capability_consumed: false,
                audit_required: false,
            }
        } else {
            SyscallResult {
                value: u64::MAX - 8, // -EBADF
                capability_consumed: false,
                audit_required: false,
            }
        }
    } else {
        SyscallResult {
            value: u64::MAX - 2, // -ENOSYS
            capability_consumed: false,
            audit_required: false,
        }
    }
}

fn handle_lseek(_fd: u64, offset_and_whence: u64) -> SyscallResult {
    let offset = (offset_and_whence >> 32) as i32 as i64;
    let _whence = offset_and_whence & 0xFFFFFFFF;
    
    // For now, just return the offset (simplified implementation)
    SyscallResult {
        value: offset as u64,
        capability_consumed: false,
        audit_required: false,
    }
}

fn handle_mkdir(path_ptr: u64, mode: u64) -> SyscallResult {
    if path_ptr == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    if let Some(vfs) = crate::fs::get_vfs() {
        unsafe {
            let path_str = core::ffi::CStr::from_ptr(path_ptr as *const i8);
            if let Ok(path) = path_str.to_str() {
                let dir_mode = crate::fs::FileMode {
                    permissions: mode as u16,
                    file_type: crate::fs::FileType::Directory,
                    setuid: false,
                    setgid: false,
                    sticky: false,
                };
                
                match vfs.create_file(path, dir_mode) {
                    Ok(_) => SyscallResult {
                        value: 0, // Success
                        capability_consumed: true,
                        audit_required: false,
                    },
                    Err(_) => SyscallResult {
                        value: u64::MAX - 17, // -EEXIST
                        capability_consumed: false,
                        audit_required: false,
                    }
                }
            } else {
                SyscallResult {
                    value: u64::MAX, // -EINVAL
                    capability_consumed: false,
                    audit_required: false,
                }
            }
        }
    } else {
        SyscallResult {
            value: u64::MAX - 2, // -ENOSYS
            capability_consumed: false,
            audit_required: false,
        }
    }
}

fn handle_rmdir(path_ptr: u64) -> SyscallResult {
    if path_ptr == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    // Simplified - would remove directory
    SyscallResult {
        value: 0, // Success
        capability_consumed: true,
        audit_required: true,
    }
}

fn handle_unlink(path_ptr: u64) -> SyscallResult {
    if path_ptr == 0 {
        return SyscallResult {
            value: u64::MAX, // -EINVAL
            capability_consumed: false,
            audit_required: false,
        };
    }
    
    // Simplified - would remove file
    SyscallResult {
        value: 0, // Success
        capability_consumed: true,
        audit_required: true,
    }
}

fn log_syscall_performance(syscall: SyscallNumber, start: u64, end: u64) {
    let duration = end - start;
    
    // Log slow syscalls
    if duration > 1000000 { // 1ms
        if let Some(logger) = crate::log::logger::try_get_logger() {
            logger.log(&format!("Slow syscall {:?}: {}ns", syscall, duration));
        }
    }
}
