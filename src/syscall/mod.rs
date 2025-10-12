#![no_std]

extern crate alloc;

pub mod nonos_capabilities;
pub mod nonos_dispatch;
pub mod nonos_handler;
pub mod nonos_validation;
pub mod nonos_vdso;
pub mod nonos_syscall;

pub use nonos_capabilities as capabilities;
pub use nonos_dispatch as dispatch;
pub use nonos_handler as handler;
pub use nonos_validation as validation;
pub use nonos_vdso as vdso;

use nonos_capabilities::current_caps;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum SyscallNumber {
    Exit   = 0,
    Read   = 1,
    Write  = 2,
    Open   = 3,
    Close  = 4,
    Stat   = 5,
    Fstat  = 6,
    Lseek  = 8,
    Mmap   = 9,
    Munmap = 11,
    Rename = 82,
    Mkdir  = 83,
    Rmdir  = 84,
    Unlink = 87,
}

impl SyscallNumber {
    #[inline]
    fn from_u64(id: u64) -> Option<Self> {
        match id {
            0 => Some(Self::Exit),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Open),
            4 => Some(Self::Close),
            5 => Some(Self::Stat),
            6 => Some(Self::Fstat),
            8 => Some(Self::Lseek),
            9 => Some(Self::Mmap),
            11 => Some(Self::Munmap),
            82 => Some(Self::Rename),
            83 => Some(Self::Mkdir),
            84 => Some(Self::Rmdir),
            87 => Some(Self::Unlink),
            _ => None,
        }
    }
}

pub struct SyscallResult {
    pub value: i64,
    pub capability_consumed: bool,
    pub audit_required: bool,
}

#[inline(always)]
fn ret_errno(e: i32) -> u64 {
    (-(e as i64)) as u64
}

#[inline(always)]
pub fn handle_syscall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let Some(sc) = SyscallNumber::from_u64(id) else {
        // -ENOSYS
        return ret_errno(38);
    };

    let caps = current_caps();
    let allowed = match sc {
        SyscallNumber::Exit   => caps.can_exit(),
        SyscallNumber::Read   => caps.can_read(),
        SyscallNumber::Write  => caps.can_write(),
        SyscallNumber::Open   => caps.can_open_files(),
        SyscallNumber::Close  => caps.can_close_files(),
        SyscallNumber::Stat   => caps.can_stat(),
        SyscallNumber::Fstat  => caps.can_stat(),
        SyscallNumber::Lseek  => caps.can_seek(),
        SyscallNumber::Mmap   => caps.can_allocate_memory(),
        SyscallNumber::Munmap => caps.can_deallocate_memory(),
        SyscallNumber::Mkdir  => caps.can_modify_dirs(),
        SyscallNumber::Rmdir  => caps.can_modify_dirs(),
        SyscallNumber::Unlink => caps.can_unlink(),
        SyscallNumber::Rename => caps.can_modify_dirs(),
    };

    if !allowed {
        // -EPERM
        return ret_errno(1);
    }

    let r = nonos_dispatch::handle_syscall_dispatch(sc, a0, a1, a2, a3, a4, a5);
    r.value as u64
}

#[no_mangle]
pub extern "C" fn handle_interrupt() {
    unsafe {
        let (rax, rdi, rsi, rdx, r10, r8, r9): (u64, u64, u64, u64, u64, u64, u64);
        core::arch::asm!(
            "mov {rax}, rax",
            "mov {rdi}, rdi",
            "mov {rsi}, rsi",
            "mov {rdx}, rdx",
            "mov {r10}, r10",
            "mov {r8},  r8",
            "mov {r9},  r9",
            rax = out(reg) rax,
            rdi = out(reg) rdi,
            rsi = out(reg) rsi,
            rdx = out(reg) rdx,
            r10 = out(reg) r10,
            r8  = out(reg) r8,
            r9  = out(reg) r9,
            options(nostack, preserves_flags),
        );
        let res = handle_syscall(rax, rdi, rsi, rdx, r10, r8, r9);
        core::arch::asm!("mov rax, {res}", res = in(reg) res, options(nostack, preserves_flags));
    }
}
