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

mod crypto;

use super::audit::{audit_syscall, SYSCALL_STATS};
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;
use core::sync::atomic::Ordering;

pub(crate) fn handle_syscall_dispatch(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    SYSCALL_STATS.total_calls.fetch_add(1, Ordering::Relaxed);
    let result = dispatch_syscall(syscall, a0, a1, a2, a3, a4, a5);
    if result.value >= 0 {
        SYSCALL_STATS.successful_calls.fetch_add(1, Ordering::Relaxed);
    } else {
        SYSCALL_STATS.failed_calls.fetch_add(1, Ordering::Relaxed);
        if result.value == -1 {
            SYSCALL_STATS.permission_denied.fetch_add(1, Ordering::Relaxed);
        }
    }
    if result.audit_required {
        audit_syscall(syscall, [a0, a1, a2, a3], &result);
    }
    result
}

fn dispatch_syscall(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    match syscall {
        // Routed to the userland crypto/entropy capsules.
        SyscallNumber::CryptoRandom
        | SyscallNumber::CryptoHash
        | SyscallNumber::CryptoEd25519Verify => {
            crypto::dispatch_crypto(syscall, a0, a1, a2, a3, a4, a5)
        }

        // Microkernel ABI. Capsule libc reaches the kernel through
        // these numbers.
        SyscallNumber::MkIpcSend
        | SyscallNumber::MkIpcRecv
        | SyscallNumber::MkIpcCall
        | SyscallNumber::MkMmap
        | SyscallNumber::MkMunmap
        | SyscallNumber::MkSpawn
        | SyscallNumber::MkExit
        | SyscallNumber::MkYield
        | SyscallNumber::MkCapGrant
        | SyscallNumber::MkCapRevoke
        | SyscallNumber::MkCapCheck
        | SyscallNumber::MkDeviceList
        | SyscallNumber::MkDeviceClaim
        | SyscallNumber::MkDeviceRelease
        | SyscallNumber::MkMmioMap
        | SyscallNumber::MkMmioUnmap
        | SyscallNumber::MkIrqBind
        | SyscallNumber::MkIrqUnbind
        | SyscallNumber::MkIrqAck
        | SyscallNumber::MkIrqPoll
        | SyscallNumber::MkDmaMap
        | SyscallNumber::MkDmaUnmap
        | SyscallNumber::MkPioGrant
        | SyscallNumber::MkPioRead
        | SyscallNumber::MkPioWrite
        | SyscallNumber::MkPioRelease
        | SyscallNumber::MkDebug => {
            let result = crate::syscall::microkernel::dispatch_microkernel_syscall(
                syscall as u64,
                a0,
                a1,
                a2,
                a3,
                a4,
                a5,
            );
            SyscallResult { value: result, capability_consumed: false, audit_required: true }
        }

        // Linux-shape numbers retained only for `from_u64` totality.
        _ => {
            log_unknown_syscall_first_per_pid(syscall);
            super::util::errno(38)
        }
    }
}

// Bounded diagnostic for capsules that hit a syscall the router does
// not handle. Prints once per pid so a misaligned userland ABI is
// visible without spamming. Returns nothing; the caller maps the
// result to ENOSYS.
fn log_unknown_syscall_first_per_pid(nr: SyscallNumber) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static SEEN_PIDS: AtomicU64 = AtomicU64::new(0);

    let pid = crate::process::current_pid().unwrap_or(0);
    if pid >= 64 {
        return;
    }
    let mask: u64 = 1u64 << pid;
    let prev = SEEN_PIDS.fetch_or(mask, Ordering::Relaxed);
    if prev & mask != 0 {
        return;
    }

    crate::sys::serial::print(b"[SYSCALL-UNKNOWN] pid=");
    crate::arch::x86_64::diag::print_hex_u64(pid as u64);
    crate::sys::serial::print(b" nr=");
    crate::arch::x86_64::diag::print_hex_u64(nr as u64);
    crate::sys::serial::println(b"");
}
