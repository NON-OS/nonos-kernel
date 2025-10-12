//! Syscall Dispatch System (ZeroState)

#![no_std]

extern crate alloc;

use alloc::string::String;

use super::{SyscallNumber, SyscallResult};

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: false }
}

/// Convert user C string (NUL-terminated) at addr into a kernel String (bounded by max_len).
fn parse_string_from_user(addr: u64, max_len: usize) -> Result<String, &'static str> {
    use alloc::vec::Vec;

    if addr == 0 {
        return Err("Null pointer");
    }
    unsafe {
        let mut v = Vec::with_capacity(64);
        let mut i = 0usize;
        loop {
            if i >= max_len {
                return Err("String too long");
            }
            let b = core::ptr::read((addr as *const u8).add(i));
            if b == 0 {
                break;
            }
            v.push(b);
            i += 1;
        }
        let s = core::str::from_utf8(&v).map_err(|_| "Invalid UTF-8")?;
        Ok(String::from(s))
    }
}

pub fn handle_syscall_dispatch(
    syscall: SyscallNumber,
    a0: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Exit   => handle_exit(a0),
        SyscallNumber::Read   => handle_read(a0 as i32, a1, a2),
        SyscallNumber::Write  => handle_write(a0 as i32, a1, a2),
        SyscallNumber::Open   => handle_open(a0, a1, a2),
        SyscallNumber::Close  => handle_close(a0 as i32),
        SyscallNumber::Stat   => handle_stat(a0, a1),
        SyscallNumber::Fstat  => handle_fstat(a0 as i32, a1),
        SyscallNumber::Lseek  => handle_lseek(a0 as i32, a1 as i64, a2 as i32),
        SyscallNumber::Mmap   => handle_mmap(a0, a1, a2, a3),
        SyscallNumber::Munmap => handle_munmap(a0, a1),
        SyscallNumber::Mkdir  => handle_mkdir(a0, a1),
        SyscallNumber::Rmdir  => handle_rmdir(a0),
        SyscallNumber::Unlink => handle_unlink(a0),
        SyscallNumber::Rename => handle_rename(a0, a1),
    }
}

// ---- Core syscalls ----

fn handle_exit(status: u64) -> SyscallResult {
    // Delegate to process layer if available; otherwise halt.
    #[allow(unused)]
    {
        if let Some(_proc) = crate::process::current_process() {
            crate::process::syscalls::sys_exit(status as i32);
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn handle_read(fd: i32, buf: u64, count: u64) -> SyscallResult {
    if buf == 0 || count == 0 || count > 0x7FFF_FFFF {
        return errno(22); // EINVAL
    }
    let ptr = buf as *mut u8;
    let n = crate::fs::read_file_descriptor(fd, ptr, count as usize);
    match n {
        Some(bytes) => SyscallResult { value: bytes as i64, capability_consumed: false, audit_required: false },
        None => errno(5), // EIO
    }
}

fn handle_write(fd: i32, buf: u64, count: u64) -> SyscallResult {
    if buf == 0 || count == 0 || count > 0x7FFF_FFFF {
        return errno(22); // EINVAL
    }
    let ptr = buf as *const u8;
    let n = crate::fs::write_file_descriptor(fd, ptr, count as usize);
    match n {
        Some(bytes) => SyscallResult { value: bytes as i64, capability_consumed: false, audit_required: false },
        None => errno(5), // EIO
    }
}

fn handle_open(pathname: u64, flags: u64, mode: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14), // EFAULT
    };
    // Build a transient null-terminated copy
    use alloc::vec::Vec;
    let mut tmp = Vec::with_capacity(s.len() + 1);
    tmp.extend_from_slice(s.as_bytes());
    tmp.push(0);

    let fd = crate::fs::open_file_syscall(tmp.as_ptr(), flags as i32, mode as u32);
    match fd {
        Some(n) => SyscallResult { value: n as i64, capability_consumed: false, audit_required: false },
        None => errno(2), // ENOENT or EACCES 
    }
}

fn handle_close(fd: i32) -> SyscallResult {
    if crate::fs::close_file_descriptor(fd) {
        SyscallResult { value: 0, capability_consumed: false, audit_required: false }
    } else {
        errno(9) // EBADF
    }
}

fn handle_stat(pathname: u64, statbuf: u64) -> SyscallResult {
    if pathname == 0 || statbuf == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    use alloc::vec::Vec;
    let mut tmp = Vec::with_capacity(s.len() + 1);
    tmp.extend_from_slice(s.as_bytes());
    tmp.push(0);

    let ok = crate::fs::stat_file_syscall(tmp.as_ptr(), statbuf as *mut u8);
    if ok { SyscallResult { value: 0, capability_consumed: false, audit_required: false } } else { errno(2) }
}

fn handle_fstat(fd: i32, statbuf: u64) -> SyscallResult {
    if statbuf == 0 {
        return errno(22);
    }
    let ok = crate::fs::fstat_file_syscall(fd, statbuf as *mut u8);
    if ok { SyscallResult { value: 0, capability_consumed: false, audit_required: false } } else { errno(9) }
}

fn handle_lseek(fd: i32, offset: i64, whence: i32) -> SyscallResult {
    match crate::fs::fd::lseek_syscall(fd, offset, whence) {
        Ok(new_off) => SyscallResult { value: new_off as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(22),
    }
}

fn handle_mkdir(pathname: u64, _mode: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.mkdir_all(&s)) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = if e == "File exists" { 17 } else { 5 };
            errno(code)
        }
    }
}

fn handle_rmdir(pathname: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.rmdir(&s)) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = match e {
                "Directory not empty" => 39, // ENOTEMPTY
                "Directory not found" => 2,  // ENOENT
                _ => 5,                      // EIO
            };
            errno(code)
        }
    }
}

fn handle_unlink(pathname: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.unlink(&s)) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = if e == "Not found" || e == "File not found" { 2 } else { 5 };
            errno(code)
        }
    }
}

fn handle_rename(oldpath: u64, newpath: u64) -> SyscallResult {
    if oldpath == 0 || newpath == 0 {
        return errno(22);
    }
    let old = match parse_string_from_user(oldpath, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let new = match parse_string_from_user(newpath, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.rename(&old, &new)) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_e) => errno(5), // EIO generic
    }
}

// Memory map via process memory manager for ZeroState
fn handle_mmap(addr: u64, length: u64, prot: u64, _flags: u64) -> SyscallResult {
    if length == 0 {
        return errno(22);
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(1); // EPERM (no process context)
    };

    // Convert protection flags to page table flags
    let mut page_flags = x86_64::structures::paging::PageTableFlags::PRESENT
        | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE;

    if (prot & 0x2) != 0 { // PROT_WRITE
        page_flags |= x86_64::structures::paging::PageTableFlags::WRITABLE;
    }
    if (prot & 0x4) == 0 { // PROT_EXEC off => NX on
        page_flags |= x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
    }

    let start_addr = if addr != 0 { Some(x86_64::VirtAddr::new(addr)) } else { None };

    match proc.mmap(start_addr, length as usize, page_flags) {
        Ok(virt) => SyscallResult { value: virt.as_u64() as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(12), // ENOMEM
    }
}

fn handle_munmap(addr: u64, length: u64) -> SyscallResult {
    if addr == 0 || length == 0 {
        return errno(22);
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(1); // EPERM
    };
    match proc.munmap(x86_64::VirtAddr::new(addr), length as usize) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(22),
    }
}
