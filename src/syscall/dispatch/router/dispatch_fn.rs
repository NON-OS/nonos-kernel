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

use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

use super::{crypto, graphics_backend, input_ops, surface_ops};

// Graphics is served by the in-kernel backend until a capsule takes
// over; all other unrouted numbers return ENOSYS. Smoke builds log a
// one-shot per pid via unknown_diag to catch capsule ABI drift.
pub(super) fn dispatch_syscall(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::CryptoRandom
        | SyscallNumber::CryptoHash
        | SyscallNumber::CryptoEd25519Verify => {
            crypto::dispatch_crypto(syscall, a0, a1, a2, a3, a4, a5)
        }
        SyscallNumber::MkIpcSend
        | SyscallNumber::MkIpcRecv
        | SyscallNumber::MkIpcCall
        | SyscallNumber::MkIpcRecvFrom
        | SyscallNumber::MkIpcSendToPid
        | SyscallNumber::MkServiceLookup
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
        nr if graphics_backend::matches(nr) => {
            graphics_backend::handle(nr, a0, a1, a2, a3, a4, a5)
        }
        SyscallNumber::MkSurfaceRegister
        | SyscallNumber::MkSurfaceShare
        | SyscallNumber::MkSurfaceAttach
        | SyscallNumber::MkSurfaceRelease
        | SyscallNumber::MkSurfacePresent
        | SyscallNumber::MkDisplayVsyncWait => surface_ops::handle(syscall, a0, a1, a2, a3, a4, a5),
        SyscallNumber::MkInputEventPost | SyscallNumber::MkInputEventDrain => {
            input_ops::handle(syscall, a0, a1, a2, a3, a4, a5)
        }
        _ => {
            #[cfg(feature = "nonos-user-entry-proof")]
            super::unknown_diag::log_first_per_pid(syscall);
            crate::syscall::dispatch::util::errno(38)
        }
    }
}
