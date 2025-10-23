// Module-level attributes removed - no_std is set at crate level

#[inline]
pub fn legacy_handle_syscall2(id: u64, a0: u64, a1: u64) -> u64 {
    super::handle_syscall(id, a0, a1, 0, 0, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall3(id: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    super::handle_syscall(id, a0, a1, a2, 0, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall4(id: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    super::handle_syscall(id, a0, a1, a2, a3, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall5(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    super::handle_syscall(id, a0, a1, a2, a3, a4, 0)
}

#[inline]
pub fn legacy_handle_syscall6(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    super::handle_syscall(id, a0, a1, a2, a3, a4, a5)
}

// (enable with `--features nonos-syscall-trace`)
#[inline(always)]
fn trace_in(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) {
    #[cfg(feature = "nonos-syscall-trace")]
    {
        crate::log_debug!("syscall in: id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}", id, a0, a1, a2, a3, a4, a5);
    }
}

#[inline(always)]
fn trace_out(id: u64, ret: u64) {
    #[cfg(feature = "nonos-syscall-trace")]
    {
        crate::log_debug!("syscall out: id={} ret={:#x}", id, ret);
    }
}

/// Legacy 3-arg gateway entry.
/// rax = id; rdi=a0; rsi=a1; rdx=a2; a3..a5 are zeroed.
#[no_mangle]
pub extern "C" fn nonos_legacy_syscall_entry() {
    unsafe {
        let (id, a0, a1, a2): (u64, u64, u64, u64);
        core::arch::asm!(
            "mov {id}, rax",
            "mov {a0}, rdi",
            "mov {a1}, rsi",
            "mov {a2}, rdx",
            id = out(reg) id,
            a0 = out(reg) a0,
            a1 = out(reg) a1,
            a2 = out(reg) a2,
            options(nostack, preserves_flags),
        );

        trace_in(id, a0, a1, a2, 0, 0, 0);
        let ret = super::handle_syscall(id, a0, a1, a2, 0, 0, 0);
        trace_out(id, ret);

        core::arch::asm!(
            "mov rax, {ret}",
            ret = in(reg) ret,
            options(nostack, preserves_flags),
        );
    }
}

/// In-kernel convenience wrappers for common operations.

#[inline]
pub fn sys_open(path_ptr: u64, flags: u64, mode: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Open as u64, path_ptr, flags, mode, 0, 0, 0) as i64
}

#[inline]
pub fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Read as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Write as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_close(fd: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Close as u64, fd, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Stat as u64, path_ptr, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_fstat(fd: u64, statbuf: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Fstat as u64, fd, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Lseek as u64, fd, offset, whence, 0, 0, 0) as i64
}

#[inline]
pub fn sys_mkdir(path_ptr: u64, mode: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Mkdir as u64, path_ptr, mode, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rmdir(path_ptr: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Rmdir as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_unlink(path_ptr: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Unlink as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rename(old_ptr: u64, new_ptr: u64) -> i64 {
    super::handle_syscall(super::SyscallNumber::Rename as u64, old_ptr, new_ptr, 0, 0, 0, 0) as i64
}
