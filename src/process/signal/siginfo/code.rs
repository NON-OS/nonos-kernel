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

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SigCode(pub i32);

impl SigCode {
    pub const USER: Self = Self(0);
    pub const KERNEL: Self = Self(0x80);
    pub const QUEUE: Self = Self(-1);
    pub const TIMER: Self = Self(-2);
    pub const MESGQ: Self = Self(-3);
    pub const ASYNCIO: Self = Self(-4);
    pub const SIGIO: Self = Self(-5);
    pub const TKILL: Self = Self(-6);

    pub const ILL_ILLOPC: Self = Self(1);
    pub const ILL_ILLOPN: Self = Self(2);
    pub const ILL_ILLADR: Self = Self(3);
    pub const ILL_ILLTRP: Self = Self(4);
    pub const ILL_PRVOPC: Self = Self(5);
    pub const ILL_PRVREG: Self = Self(6);
    pub const ILL_COPROC: Self = Self(7);
    pub const ILL_BADSTK: Self = Self(8);

    pub const FPE_INTDIV: Self = Self(1);
    pub const FPE_INTOVF: Self = Self(2);
    pub const FPE_FLTDIV: Self = Self(3);
    pub const FPE_FLTOVF: Self = Self(4);
    pub const FPE_FLTUND: Self = Self(5);
    pub const FPE_FLTRES: Self = Self(6);
    pub const FPE_FLTINV: Self = Self(7);
    pub const FPE_FLTSUB: Self = Self(8);

    pub const SEGV_MAPERR: Self = Self(1);
    pub const SEGV_ACCERR: Self = Self(2);
    pub const SEGV_BNDERR: Self = Self(3);
    pub const SEGV_PKUERR: Self = Self(4);

    pub const BUS_ADRALN: Self = Self(1);
    pub const BUS_ADRERR: Self = Self(2);
    pub const BUS_OBJERR: Self = Self(3);
    pub const BUS_MCEERR_AR: Self = Self(4);
    pub const BUS_MCEERR_AO: Self = Self(5);

    pub const TRAP_BRKPT: Self = Self(1);
    pub const TRAP_TRACE: Self = Self(2);
    pub const TRAP_BRANCH: Self = Self(3);
    pub const TRAP_HWBKPT: Self = Self(4);

    pub const CLD_EXITED: Self = Self(1);
    pub const CLD_KILLED: Self = Self(2);
    pub const CLD_DUMPED: Self = Self(3);
    pub const CLD_TRAPPED: Self = Self(4);
    pub const CLD_STOPPED: Self = Self(5);
    pub const CLD_CONTINUED: Self = Self(6);

    pub const POLL_IN: Self = Self(1);
    pub const POLL_OUT: Self = Self(2);
    pub const POLL_MSG: Self = Self(3);
    pub const POLL_ERR: Self = Self(4);
    pub const POLL_PRI: Self = Self(5);
    pub const POLL_HUP: Self = Self(6);

    pub const SYS_SECCOMP: Self = Self(1);
}
